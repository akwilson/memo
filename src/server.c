/**
 * Memo - a publish / subscribe message bus.
 *
 * Memo accepts client connections and allows them to register a subscription to
 * a topic. Other clients will publish messages to that topic and Memo will send
 * those messages on to topic subscribers. Messages are byte arrays which are
 * encoded in the following format:
 *
 * 0x00 - 0x03 - message length
 * 0x04 - 0x05 - message type
 * 0x06 - 0x45 - the message topic
 * 0x50 - EOM  - message body
 *
 * IO is handled by the io_uring API. When Memo starts it registers a pool of
 * buffers of `DEFAULT_MSG_LEN` with the io_uring and then listens for
 * connections on a socket. Memo will read data into one of the pool buffers, if
 * a message cannot fit within that buffer another buffer of length defined in
 * the message header is allocated for it. When a message is read completely the
 * buffer is considered "checked out" of the pool to be returned only when all
 * subscribers have received the message. The cost of this is that there is a
 * potential for pool starvation but it has the benefit of avoiding expensive
 * memory copying operations between read and write buffers.
 *
 * Because Memo uses TCP, a pool buffer can contain one or more messages. We
 * need to track when a buffer is checked out of the pool and when it should be
 * checked back in. This is acheived by allocating a four byte header to each
 * buffer which contains the buffer's ID (required for returning the buffer to
 * the pool) and a reference count of the number of in-flight messages contained
 * within it. When the count drops to zero the buffer is ready to be returned to
 * the pool. Memo messages contain a pointer back to this header so it can be
 * increased and decreased when a message is enqued for writing or writing has
 * completed.
 *
 * For non-pool buffers the buffer ID in the header is set to
 * `HDR_BID_NON_POOL`. These buffers are freed on write completion rather than
 * returned to a pool. This is likely to change soon.
 */

#include <stddef.h>
#include <signal.h>
#include <sys/signalfd.h>

#include "logging.h"
#include "memo_int.h"

#define BACKLOG 10 // Number of pending connections the queue will hold.
#define QUEUE_DEPTH 256
#define MSG_QUEUE_SIZE 32
#define DEFAULT_MSG_LEN 4096
#define PARTIAL_MSG_LEN 72
#define READ_BUF_SZE 4096
#define READ_BUF_NUM 32
#define READ_BUF_BID 1

/*
 * Defines to manage bit packing of buffer headers:
 * low bits for writer_count, high bits for buffer_id
 */
#define HDR_WRITERS_BITS 16u
#define HDR_BID_BITS     (32u - HDR_WRITERS_BITS)

// Basic sanity checks
#if (HDR_WRITERS_BITS == 0) || (HDR_BID_BITS == 0) || (HDR_WRITERS_BITS + HDR_BID_BITS != 32)
#error "Invalid header bit layout: WRITERS_BITS and BID_BITS must be > 0 and sum to 32."
#endif

// Masks & shifts
#define HDR_WRITERS_MASK   ((uint32_t)((1u << HDR_WRITERS_BITS) - 1u))
#define HDR_BID_SHIFT      (HDR_WRITERS_BITS)
#define HDR_BID_VALUE_MASK ((uint32_t)((1u << HDR_BID_BITS) - 1u))
#define HDR_BID_MASK       (HDR_BID_VALUE_MASK << HDR_BID_SHIFT)

// Special ID value meaning 'non-pool' (all ones in the ID field)
#define HDR_BID_NON_POOL  (HDR_BID_VALUE_MASK)

#define max(x,y) ((x) > (y) ? (x) : (y))
#define msg_len(b) (*((uint32_t *)(b)))

/**
 * The current state of a connection represents what it
 * was doing when it returns from the io_uring.
 */
typedef enum
{
    CONN_ACCEPT,
    CONN_READ,
    CONN_WRITE,
    CONN_SIGNAL
} conn_state_e;

/**
 * A message queue for messages pending write on a
 * connection. Implemented as a ring buffer.
 */
typedef struct message_queue
{
    unsigned   write;
    unsigned   read;
    memo_msg_s data[MSG_QUEUE_SIZE];
} message_queue_s;

typedef struct connection connection_s;

/**
 * The `user_data` reference on the io_uring. We get this back on the CQE from io_uring and
 * from here we can tell if the response we need to process is an accept, read or write.
 */
typedef struct op_context
{
    conn_state_e state;
    connection_s *conn;
} op_context_s;

/**
 * An external connection from a Memo client.
 */
struct connection
{
    int               socket;

    data_slice_s      read_buf;  // points to a pool or specially allocated buffer
    size_t            bytes_r;   // number of bytes read so far
    memo_msg_s        write_msg; // current message being written to this connection
    uint32_t          bytes_w;   // number of bytes written so far

    op_context_s      accept_op;
    op_context_s      read_op;
    op_context_s      write_op;

    message_queue_s   *mq;

    struct connection *next_s;   // linked list for the subscription
    struct connection *next_r;   // linked list for the server
};

/**
 * Connections subscribing to a given topic.
 */
typedef struct subscription
{
    char                topic[TOPIC_LEN];
    connection_s        *connections;
    struct subscription *next;
} subscription_s;

struct memo_server
{
    int                      listener;

    int                      signalfd;
    struct signalfd_siginfo  *siginfo;
    op_context_s             signal_op;

    struct io_uring          *ring;
    connection_s             *connections;
    subscription_s           *subscriptions;

    struct io_uring_buf_ring *read_buf_ring;
    uint8_t                  *read_buf_base; // memory allocated for pool buffers + their headers
};

/*
 * Functions for dealing with the buffer header.
 */

static inline uint32_t hdr_get_bid(uint32_t header)
{
    return (header >> HDR_BID_SHIFT) & HDR_BID_VALUE_MASK;
}

static inline void hdr_set_bid(uint32_t *header, uint32_t bid)
{
    *header = (*header & ~HDR_BID_MASK) | ((bid & HDR_BID_VALUE_MASK) << HDR_BID_SHIFT);
}

static inline bool hdr_is_pool(uint32_t header)
{
    return hdr_get_bid(header) != HDR_BID_NON_POOL;
}

static inline void hdr_set_nonpool(uint32_t *header)
{
    hdr_set_bid(header, HDR_BID_NON_POOL);
}

static inline uint32_t hdr_get_writers(uint32_t header)
{
    return header & HDR_WRITERS_MASK;
}

static inline void hdr_set_writers(uint32_t *header, uint32_t count)
{
    *header = (*header & ~HDR_WRITERS_MASK) | (count & HDR_WRITERS_MASK);
}

static inline uint32_t hdr_inc_writers(uint32_t *header)
{
    uint32_t c = hdr_get_writers(*header);
    if (c == HDR_WRITERS_MASK)
        return -1; // overflow
    hdr_set_writers(header, c + 1);
    return hdr_get_writers(*header);
}

static inline uint32_t hdr_dec_writers(uint32_t *header)
{
    uint32_t c = hdr_get_writers(*header);
    if (c == 0)
        return -1; // underflow
    hdr_set_writers(header, c - 1);
    return hdr_get_writers(*header);
}

static inline uint32_t *hdr_get_header(uint8_t *buf)
{
    return ((uint32_t *)buf) - 1;
}

static inline uint8_t *hdr_get_buf(uint32_t *header)
{
    return (uint8_t *)(header + 1);
}

static inline uint32_t hdr_get_val(uint8_t *buf)
{
    return *hdr_get_header(buf);
}

/*
 * Message functions.
 */

/**
 * Parses out a `memo_msg_s` from a `data_slice_s`. Assumes
 * that the slice contains at least one complete message.
 *
 * @param `slice`  a chunk of memory within a data buffer
 * @param `header` pointer to the buffer's four byte header
 *
 * @returns a `memo_msg_s` pointing to the message within the slice
 */
static memo_msg_s msg_parse(data_slice_s slice, uint32_t *header)
{
    uint32_t msg_len = *((uint32_t *)slice.ptr);
    return (memo_msg_s)
    {
        .msg_len = msg_len,
        .type = *((uint8_t *)(slice.ptr + sizeof(uint32_t))),
        .topic = (const char *)(slice.ptr + sizeof(uint32_t) + sizeof(uint8_t)),
        .body = slice.ptr + MSG_HEADER_LEN,
        .body_len = msg_len - MSG_HEADER_LEN,
        ._raw_data = slice.ptr,
        ._header = header
    };
}

/**
 * Checks to see of a `memo_msg_s` is NULL, i.e. points to nothing.
 */
static inline bool msg_is_null(memo_msg_s msg)
{
    return msg._raw_data == NULL;
}

/**
 * Sets a `memo_msg_s` to NULL.
 */
static inline void msg_set_null(memo_msg_s *msg)
{
    *msg = (memo_msg_s){0};
}

static void msg_log_pub(memo_msg_s msg, int num_writers)
{
    if (num_writers)
    {
        log_info("Publishing %d bytes on '%s' to %d subscribers",
                 msg.msg_len, msg.topic, num_writers);
        size_t print_len = msg.body_len < 64 ? msg.body_len : 64;
        log_debug("body: %.*s", print_len, (char *)msg.body);
    }
    else
    {
        log_debug("No subscribers found for %d byte message on '%s', message dropped",
                  msg.msg_len, msg.topic);
    }
}

/**
 * Adds a message to a message queue.
 *
 * @param `mq`  the message queue to add to.
 * @param `msg` the memo message to enqueue.
 *
 * @returns `true` if the message was successfully, `false` if the queue is already full.
 */
static bool msg_queue_push(message_queue_s *mq, memo_msg_s msg)
{
    size_t next_head = (mq->write + 1) % MSG_QUEUE_SIZE;
    if (next_head == mq->read)
    {
        // Queue is full
        return false;
    }

    mq->data[mq->write] = msg;
    mq->write = next_head;
    return true;
}

/**
 * Pops the next item off the end of the message queue.
 *
 * @param `mq`  the message queue to read from.
 * @param `msg` out param, set to the item if found.
 *
 * @returns `true` if a value was found, false if the queue is empty.
 */
static bool msg_queue_pop(message_queue_s *mq, memo_msg_s *msg)
{
    if (mq->read == mq->write)
    {
        // Queue is empty
        return false;
    }

    *msg = mq->data[mq->read];
    msg_set_null(&mq->data[mq->read]);
    mq->read = (mq->read + 1) % MSG_QUEUE_SIZE;
    return true;
}

static void free_connection(connection_s *conn)
{
    close(conn->socket);
    free(conn->mq);
    free(conn);
}

/**
 * Finds a pool buffer for the given buffer id.
 */
static inline uint8_t *find_buf(memo_server_s *server, uint32_t bid)
{
    return server->read_buf_base + (bid * READ_BUF_SZE) + ((bid + 1) * sizeof(uint32_t));
}

/**
 * Creates a file descriptor for handling kill signals. Will be fed in to the io_uring.
 */
static int setup_signal_fd()
{
    sigset_t set;

    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);

    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1)
        return -1;

    int sfd = signalfd(-1, &set, SFD_CLOEXEC | SFD_NONBLOCK);
    return sfd;
}

/**
 * Sets up the io_uring read buffers.
 *
 * Allocates memory for io_uring's buffer ring, `READ_BUF_NUM` buffers and a header for each. The
 * header is a `uint32_t` which is packed with two values: the buffer id and a counter of the
 * number of writers referencing messages within it. This reference counter is decremented
 * when a message completes sending; when it drops to zero the buffer can be returned to the pool.
 *
 * The buffer id is stored because it is needed by the io_uring function to return the buffer
 * to the pool and this is the most convenient place to keep it.
 */
static bool setup_read_buffers(memo_server_s *server)
{
    struct io_uring_buf_ring *br;

    // allocating io_uring_buf + an actual buffer + a header in the buffer to track senders
    size_t total_buf_size = (sizeof(struct io_uring_buf) + READ_BUF_SZE + sizeof(uint32_t)) * READ_BUF_NUM;
    if (posix_memalign((void **)&br, READ_BUF_SZE, total_buf_size))
        return true;

    memset(br, 0, total_buf_size);
    struct io_uring_buf_reg reg =
    {
        .ring_addr = (unsigned long)br,
        .ring_entries = READ_BUF_NUM,
        .bgid = READ_BUF_BID
    };

    if (io_uring_register_buf_ring(server->ring, &reg, 0))
        return true;

    server->read_buf_ring = br;
    server->read_buf_base = (uint8_t *)br + sizeof(struct io_uring_buf) * READ_BUF_NUM;

    io_uring_buf_ring_init(br);
    for (int i = 0; i < READ_BUF_NUM; i++)
    {
        uint8_t *nb = find_buf(server, i);
        uint32_t *header = hdr_get_header(nb);
        hdr_set_bid(header, i);
        hdr_set_writers(header, 0);
        
        io_uring_buf_ring_add(br, nb, READ_BUF_SZE, i, io_uring_buf_ring_mask(READ_BUF_NUM), i);
    }

    io_uring_buf_ring_advance(br, READ_BUF_NUM);
    return false;
}

/**
 * The initial read of a message will always come from a pool buffer. If this is the
 * initial read then identify the buffer and set up the connection's `read_buf`.
 *
 * @param `conn`  the connection whose `read_buf` will be set.
 * @param `flags` flags from the io_uring CQE, contains the buffer id.
 */
static void set_read_buffer(memo_server_s *server, connection_s *conn, uint32_t flags)
{
    if (conn->read_buf.ptr == NULL)
    {
        uint32_t buffer_id = flags >> IORING_CQE_BUFFER_SHIFT;
        log_debug("Reading from buffer %d", buffer_id);
        conn->read_buf.len = READ_BUF_SZE;
        conn->read_buf.ptr = find_buf(server, buffer_id);
    }
}

/**
 * Gets the IP address, either IPv4 or IPv6.
 */
static void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/**
 * Sets up the connection with the socket and logs some connection details.
 */
static void initialise_connection(connection_s *conn, int socket, struct sockaddr_storage *their_addr)
{
    char s[INET6_ADDRSTRLEN];

    conn->socket = socket;

    inet_ntop(their_addr->ss_family, get_in_addr((struct sockaddr *)their_addr), s, sizeof s);
    log_info("Accepted connection %d from %s", socket, s);
}

/**
 * Sets up the signal file descriptor with the io_uring.
 */
static void prepare_signals(memo_server_s *server)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(server->ring);
    io_uring_prep_read(sqe, server->signalfd, server->siginfo, sizeof(struct signalfd_siginfo), 0);

    server->signal_op.conn = NULL;
    server->signal_op.state = CONN_SIGNAL;
    io_uring_sqe_set_data(sqe, &server->signal_op);

    io_uring_submit(server->ring);
}

/**
 * Sets up an accept request in the io_uring submission queue in
 * preparation for establishing new client connections.
 */
static void prepare_accept(memo_server_s *server, struct sockaddr_storage *their_addr, socklen_t *their_addr_len)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(server->ring);
    io_uring_prep_accept(sqe, server->listener, (struct sockaddr *)their_addr,
                         their_addr_len, SOCK_NONBLOCK);

    connection_s *conn = calloc(1, sizeof(connection_s));
    conn->next_r = server->connections;
    server->connections = conn;

    conn->accept_op.conn = conn;
    conn->accept_op.state = CONN_ACCEPT;
    conn->mq = calloc(1, sizeof(message_queue_s));

    log_debug("Preparing to accept");
    io_uring_sqe_set_data(sqe, &conn->accept_op);
    io_uring_submit(server->ring);
}

/**
 * Helper function to prepare a recv call on the io_uring.
 */
static void prepare_recv(memo_server_s *server, connection_s *conn, void *buf, size_t length)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(server->ring);

    conn->read_op.conn = conn;
    conn->read_op.state = CONN_READ;

    log_debug("Preparing to read %ld bytes on client %d using %spool buffer",
             length, conn->socket, buf == NULL ? "" : "non-");
    io_uring_prep_recv(sqe, conn->socket, buf, length, 0);

    if (buf == NULL)
    {
        // Using a pool buffer
        sqe->flags |= IOSQE_BUFFER_SELECT;
        sqe->buf_group = READ_BUF_BID;
    }

    io_uring_sqe_set_data(sqe, &conn->read_op);
    io_uring_submit(server->ring);
}

/**
 * Returns a read buffer to the global pool. Everything we need is accessible
 * from the buffer's header.
 */
static void recycle_read_buf(memo_server_s *server, uint32_t *header)
{
    uint32_t bid = hdr_get_bid(*header);
    uint8_t  *buf = hdr_get_buf(header);

    log_debug("Recycling pool buffer %d", bid);
    io_uring_buf_ring_add(server->read_buf_ring, buf, READ_BUF_SZE, bid,
                          io_uring_buf_ring_mask(READ_BUF_NUM), 0);
    io_uring_buf_ring_advance(server->read_buf_ring, 1);
}

/**
 * If a connection has no senders then recycle its `read_buf`.
 */
static void check_recycle_read_buf(memo_server_s *server, connection_s *conn)
{
    if (hdr_get_writers(hdr_get_val(conn->read_buf.ptr)) == 0)
        recycle_read_buf(server, hdr_get_header(conn->read_buf.ptr));
}

/**
 * Enqueues a read request for the default message size worth of data from the
 * connection. This includes a message header and a bit of extra room for a message
 * body. If the whole message fails to fit within this block we will enqueue another
 * read for what remains.
 */
static void read_from_start(memo_server_s *server, connection_s *conn)
{
    conn->read_buf.len = 0;
    conn->read_buf.ptr = NULL;
    conn->bytes_r = 0;

    prepare_recv(server, conn, NULL, DEFAULT_MSG_LEN);
}

/**
 * Checks the environment to see if we are forcing partial writes. Useful for testing
 * and debugging.
 */
static bool get_env_partial_writes()
{
    static const char *pw = NULL;
    if (pw == NULL)
    {
        const char *env = getenv("MEMO_PARTIAL_WRITE");
        pw = (env != NULL) ? env : "N";
    }

    return pw[0] == 'Y';
}

/**
 * Helper function to prepare a send over the io_uring.
 */
static void prepare_write(memo_server_s *server, connection_s *dest, const void *buf, size_t length)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(server->ring);

    dest->write_op.conn = dest;
    dest->write_op.state = CONN_WRITE;

    if (get_env_partial_writes())
    {
        length = length > PARTIAL_MSG_LEN ? PARTIAL_MSG_LEN : length;
        log_debug("Preparing partial write %ld bytes to client %d", length, dest->socket);
    }
    else
    {
        log_debug("Preparing to write %ld bytes to client %d", length, dest->socket);
    }

    io_uring_prep_write(sqe, dest->socket, buf, length, 0);
    io_uring_sqe_set_data(sqe, &dest->write_op);
    io_uring_submit(server->ring);
}

/**
 * Finds the `subscription_s` for the given topic.
 *
 * @returns The `subscription_s` if found, NULL otherwise.
 */
static subscription_s *find_subscription(memo_server_s *server, const char *topic)
{
    subscription_s *sub;
    for (sub = server->subscriptions; sub; sub = sub->next)
    {
        if (!memcmp(sub->topic, topic, TOPIC_LEN))
            break;
    }

    return sub;
}

/**
 * Adds a new subscription to the server. A new `subscription_s` is created
 * if necessary and the connection registered as being interested in the
 * topic. When messages appear on the topic they will be sent to each
 * connection on the subscription.
 */
static void register_subscription(memo_server_s *server, connection_s *conn, const char *topic)
{
    subscription_s *sub = find_subscription(server, topic);
    if (!sub)
    {
        sub = calloc(1, sizeof(subscription_s));
        memcpy(sub->topic, topic, TOPIC_LEN);

        sub->next = server->subscriptions;
        server->subscriptions = sub;
    }

    conn->next_s = sub->connections;
    sub->connections = conn;

    log_info("Connection %d subscribed to '%s'", conn->socket, topic);
}

/**
 * Starts a publish operation on the next item in the connection_s's
 * message queue. Does nothing if the queue is empty.
 */
static void dequeue_publish(memo_server_s *server, connection_s *conn)
{
    memo_msg_s data;
    if (!msg_queue_pop(conn->mq, &data))
        return;

    conn->write_msg = data;
    conn->bytes_w = 0;

    prepare_write(server, conn, data._raw_data, data.msg_len);
}

/**
 * Recycles the read pool buffer if no more writes reference it. Frees non pool buffers.
 */
static void mark_send_complete(memo_server_s *server, memo_msg_s msg)
{
    if (hdr_dec_writers(msg._header) == 0)
    {
        if (hdr_is_pool(*msg._header))
        {
            recycle_read_buf(server, msg._header);
        }
        else
        {
            log_debug("Freeing non-pool buffer");
            free(msg._header);
        }
    }
}

/**
 * Publishes a message to any interested subscribers.
 *
 * @param `server` the memo server instance
 * @param `msg`    the message to send to any interested subscribers
 */
static void publish_msg(memo_server_s *server, memo_msg_s msg)
{
    subscription_s *sub = find_subscription(server, msg.topic);
    if (!sub)
    {
        msg_log_pub(msg, 0);
        return;
    }

    int i = 0;
    for (connection_s *s = sub->connections; s; s = s->next_s)
    {
        if (!msg_queue_push(s->mq, msg))
        {
            log_warn("Message queue full on client %d. Message dropped.", s->socket);
            continue;
        }

        hdr_inc_writers(msg._header);
        i++;

        if (msg_is_null(s->write_msg))
            dequeue_publish(server, s);
    }

    msg_log_pub(msg, i);
}

/**
 * Processes a fully read message from a client connection.
 */
static void process_msg(memo_server_s *server, connection_s *conn, memo_msg_s msg)
{
    switch (msg.type)
    {
    case OP_SUBSCRIBE:
        register_subscription(server, conn, msg.topic);
        break;
    case OP_PUBLISH:
        publish_msg(server, msg);
        break;
    }
}

/**
 * Parses and processes any complete messages in the buffer.
 *
 * @returns the slice of data that contains an incomplete message
 */
static data_slice_s try_process_messages(memo_server_s *server, connection_s *conn, data_slice_s slice)
{
    if (slice.len < MSG_HEADER_LEN || slice.len < msg_len(slice.ptr))
        return slice;

    memo_msg_s msg = msg_parse(slice, hdr_get_header(conn->read_buf.ptr));
    process_msg(server, conn, msg);

    data_slice_s next =
    {
        .ptr = slice.ptr + msg.msg_len,
        .len = slice.len - msg.msg_len
    };

    return try_process_messages(server, conn, next);
}

/**
 * The buffer from `recv` contains part of a message and needs to be handled.
 *
 * The three possible scenarios are:
 * 1. A single message but one too large for the default allocated buffer.
 * 2. A tiny bit of data too small for even a message header.
 * 3. Several messages, the last of which does not fit within the allocated buffer.
 *
 * This function decides what to do with whatever is there. It will reallocate the
 * buffer if it's not big enough or move the data back to the start of the buffer
 * if it is (or the size is unknown).
 *
 * @param `conn`   the connection, contains the buffer populated by `recv`
 * @param `slice`  points to the unhandled data
 *
 * @returns the amount of data to request in the next `recv` call
 */
static size_t prepare_next_read(memo_server_s *server, connection_s *conn, data_slice_s slice)
{
    ptrdiff_t unhandled_len = slice.len; // read in but not yet processed

    // Scenario 1: we're gonna need a bigger boat
    if (unhandled_len > MSG_HEADER_LEN && msg_len(slice.ptr) > conn->read_buf.len)
    {
        size_t new_buf_len = max(msg_len(slice.ptr), DEFAULT_MSG_LEN) + sizeof(uint32_t);
        uint8_t *new_buf = calloc(1, new_buf_len);
        hdr_set_nonpool((uint32_t *)new_buf);
        new_buf += sizeof(uint32_t);
        new_buf_len -= sizeof(uint32_t);
        memcpy(new_buf, slice.ptr, msg_len(slice.ptr));

        check_recycle_read_buf(server, conn);

        conn->read_buf.ptr = new_buf;
        conn->read_buf.len = new_buf_len;
        conn->bytes_r = unhandled_len;

        return msg_len(conn->read_buf.ptr) - unhandled_len;
    }

    // Scenarios 2 and 3
    if (slice.ptr > conn->read_buf.ptr)
    {
        conn->bytes_r = unhandled_len;
        memmove(conn->read_buf.ptr, slice.ptr, unhandled_len);
    }

    return conn->read_buf.len - unhandled_len;
}

/**
 * Process a signal caught by the server's `signalfd`. Graceful shutdown
 * should be handled from here.
 *
 * @returns `true` to indicate that the server should shut down, `false` otherwise
 */
static bool handle_signal(memo_server_s *server, size_t bytes_read)
{
    log_info("Caught signal. Shutting down.");
    if (bytes_read == sizeof(struct signalfd_siginfo))
    {
        int signo = server->siginfo->ssi_signo;
        if (signo == SIGINT || signo == SIGTERM)
        {
            return true;
        }
    }

    return false;
}

/**
 * Processes a message received from `recv`. Parses and processes any complete
 * messages received and decides what to do with incomplete messages.
 *
 * @param `conn`       the connection with a populated buffer to process
 * @param `bytes_read` the number of bytes in the buffer that were just populated
 *
 * @returns the number of bytes to read in the next `recv` call
 */
static size_t handle_read_response(memo_server_s *server, connection_s *conn, size_t bytes_read, uint32_t flags)
{
    set_read_buffer(server, conn, flags);

    conn->bytes_r += bytes_read;
    data_slice_s slice =
    {
        .ptr = conn->read_buf.ptr,
        .len = conn->bytes_r
    };

    data_slice_s remaining = try_process_messages(server, conn, slice);
    if (remaining.len)
    {
        return prepare_next_read(server, conn, remaining);
    }

    check_recycle_read_buf(server, conn);
    return 0;
}

/**
 * Process the result of a send. Determines if we completed a partial write and
 * another send call needs to be made or of the whole message has been sent completely.
 *
 * @param `conn`          the connection that just completed a send call
 * @param `bytes_written` the number of bytes completed by the send call
 *
 * @returns the number of bytes to be sent in the next call, 0 if completed
 */
static size_t handle_write_response(memo_server_s *server, connection_s *conn, size_t bytes_written)
{
    conn->bytes_w += bytes_written;
    if (conn->bytes_w == conn->write_msg.msg_len)
    {
        log_info("Write of %d bytes complete on '%s' to client %d",
                 conn->bytes_w, conn->write_msg.topic, conn->socket);
        mark_send_complete(server, conn->write_msg);
        msg_set_null(&conn->write_msg);
        conn->bytes_w = 0;
        return 0;
    }

    return conn->write_msg.msg_len - conn->bytes_w;
}

memo_server_s *memo_server_init(const char *port)
{
    int             sockfd;
    int             yes = 1;
    int             rv;
    struct addrinfo hints;
    struct addrinfo *servinfo;
    struct addrinfo *p;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0)
    {
        log_error("getaddrinfo: %s", gai_strerror(rv));
        return NULL;
    }

    // Loop through all the results and bind to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            perror("setsockopt");
            return NULL;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == 0)
        {
            // Socket set up successfully.
            break;
        }

        close(sockfd);
    }

    if (p == NULL)
    {
        log_error("server: failed to bind");
        return NULL;
    }

    freeaddrinfo(servinfo);

    if (listen(sockfd, BACKLOG) == -1)
    {
        perror("listen");
        return NULL;
    }

    memo_server_s *svr = calloc(1, sizeof(memo_server_s));
    svr->listener = sockfd;
    svr->ring = malloc(sizeof(struct io_uring));
    io_uring_queue_init(QUEUE_DEPTH, svr->ring, 0);

    svr->signalfd = setup_signal_fd();
    if (svr->signalfd == -1)
    {
        log_error("Failed to setup signal file descriptor");
        return NULL;
    }

    svr->siginfo = calloc(1, sizeof(struct signalfd_siginfo));

    if (setup_read_buffers(svr))
    {
        log_error("Failed to setup read buffers");
        return NULL;
    }
    
    return svr;
}

int memo_server_process(memo_server_s *server)
{
    struct io_uring_cqe     *cqe;
    struct sockaddr_storage their_addr = {0};
    socklen_t               their_addr_len = sizeof(their_addr);

    prepare_accept(server, &their_addr, &their_addr_len);
    prepare_signals(server);
    log_info("Memo Server ready");

    while (1)
    {
        int rv = io_uring_wait_cqe(server->ring, &cqe);
        if (rv < 0)
        {
            perror("io_uring_wait_cqe");
            return 1;
        }

        if (cqe->res < 0)
        {
            log_error("Async request failed: '%s'", strerror(-cqe->res));
            return 1;
        }

        op_context_s *ctx = (op_context_s *)cqe->user_data;
        connection_s *conn = ctx->conn;
        if (cqe->res == 0)
        {
            log_info("Closed connection %d", conn->socket);
            close(conn->socket);
            io_uring_cqe_seen(server->ring, cqe);
            // TODO: remove connection from server.connections or tombstone it
            continue;
        }

        switch (ctx->state)
        {
        case CONN_SIGNAL:
            if (handle_signal(server, cqe->res))
                return 0;
            prepare_signals(server);
            break;
        case CONN_ACCEPT:
            initialise_connection(conn, cqe->res, &their_addr);
            prepare_accept(server, &their_addr, &their_addr_len);
            read_from_start(server, conn);
            break;
        case CONN_READ:
            {
                size_t next_read = handle_read_response(server, conn, cqe->res, cqe->flags);
                if (next_read > 0)
                    prepare_recv(server, conn, conn->read_buf.ptr + conn->read_buf.len - next_read, next_read);
                else
                    read_from_start(server, conn);
                break;
            }
        case CONN_WRITE:
            {
                uint32_t next_write = handle_write_response(server, conn, cqe->res);
                if (next_write)
                    prepare_write(server, conn, conn->write_msg._raw_data + conn->bytes_w, next_write);
                else
                    dequeue_publish(server, conn);
            }
            break;
        }

        io_uring_cqe_seen(server->ring, cqe);
    }
}

void memo_server_free(memo_server_s *server)
{
    for (subscription_s *ptr = server->subscriptions; ptr; ptr = server->subscriptions)
    {
        if (ptr)
            server->subscriptions = ptr->next;
        free(ptr);
    }

    for (connection_s *ptr = server->connections; ptr; ptr = server->connections)
    {
        if (ptr)
            server->connections = ptr->next_r;
        free_connection(ptr);
    }

    if (server->ring != NULL)
    {
        io_uring_queue_exit(server->ring);
        io_uring_unregister_buf_ring(server->ring, READ_BUF_BID);

        free(server->read_buf_ring);
        close(server->listener);
        close(server->signalfd);

        free(server->siginfo);
        free(server->ring);
    }

    free(server);
}
