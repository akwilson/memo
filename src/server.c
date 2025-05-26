#include <stddef.h>

#include "logging.h"
#include "memo_int.h"

#define BACKLOG 10 // Number of pending connections the queue will hold.
#define QUEUE_DEPTH 256
#define MSG_QUEUE_SIZE 32
#define DEFAULT_MSG_LEN 4096
#define PARTIAL_MSG_LEN 72

#define max(x,y) ((x) > (y) ? (x) : (y))
#define msg_len(b) (*((uint32_t *)(b)))
#define slice_len(s) ((s).end - (s).start)

/**
 * The current state of a connection represents what it
 * was doing when it returns from the io_uring.
 */
typedef enum
{
    CONN_ACCEPT,
    CONN_READ,
    CONN_WRITE
} conn_state_e;

/**
 * A slice of data within a `data_buffer_s`.
 */
typedef struct
{
    uint8_t *start;
    uint8_t *end;
} data_buffer_slice_s;

/**
 * A fixed format message sent to Memo from a client.
 */
typedef struct message
{
    // Header
    uint32_t msg_size;         // total message size including the header
    uint8_t  type;             // if the message is a publish, subscribe or something else
    char     topic[TOPIC_LEN]; // the message topic
    // Body
    uint8_t  body[];           // the message to be published, unset for subscriptions
} message_s;

/**
 * A message queue for messages pending write on a
 * connection. Implemented as a ring buffer.
 */
typedef struct message_queue
{
    unsigned      write;
    unsigned      read;
    data_buffer_s *data[MSG_QUEUE_SIZE];
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

    data_buffer_s     *read_buf;
    size_t            bytes_r;
    data_buffer_s     *write_buf;
    uint32_t          bytes_w;

    op_context_s      accept_op;
    op_context_s      read_op;
    op_context_s      write_op;

    message_queue_s   *mq;

    struct connection *next_s; // linked list for the subscription
    struct connection *next_r; // linked list for the server
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
    int             listener;
    struct io_uring *ring;
    connection_s    *connections;
    subscription_s  *subscriptions;
};

/**
 * Adds a data buffer to the message queue.
 *
 * @param `mq`  the message queue to add to.
 * @param `buf` the buffer to enqueue.
 *
 * @returns `true` if the buffer was successfully enqueued, `false` if the queue is already full.
 */
static bool msg_queue_push(message_queue_s *mq, data_buffer_s *buf)
{
    size_t next_head = (mq->write + 1) % MSG_QUEUE_SIZE;
    if (next_head == mq->read)
    {
        // Queue is full
        return false;
    }

    mq->data[mq->write] = buf;
    mq->write = next_head;
    return true;
}

/**
 * Pops the next item off the end of the message queue.
 *
 * @param 'mq' the message queue to read from.
 *
 * @returns the next buffer in the queue, NULL if the queue is empty.
 */
static data_buffer_s *msg_queue_pop(message_queue_s *mq)
{
    if (mq->read == mq->write)
    {
        // Queue is empty
        return NULL;
    }

    data_buffer_s *rv = mq->data[mq->read];
    mq->data[mq->read] = NULL;
    mq->read = (mq->read + 1) % MSG_QUEUE_SIZE;
    return rv;
}


static void free_subscription(subscription_s *sub)
{
    free(sub->topic);
    free(sub);
}

static void free_connection(connection_s *conn)
{
    close(conn->socket);
    free(conn->mq);
    free(conn);
}

static void print_message(message_s *message)
{
    log_debug("size: %d", message->msg_size);
    log_debug("type: %s", message->type == OP_PUBLISH ? "Publish" : "Subscribe");
    log_debug("topic: %s", message->topic);
    if (message->type == OP_PUBLISH)
    {
        unsigned body_len = message->msg_size - MSG_HEADER_LEN;
        if (body_len < 64)
            log_debug("body: %.*s", body_len, (char *)message->body);
        else
            log_debug("body: %.*s...", 64, (char *)message->body);
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
 * Sets up the connection with the socket details and logs some connection details.
 */
static void initialise_connection(connection_s *conn, int socket, struct sockaddr_storage *their_addr)
{
    char s[INET6_ADDRSTRLEN];

    conn->socket = socket;
    conn->read_buf = calloc(1, sizeof(data_buffer_s) + DEFAULT_MSG_LEN);
    conn->read_buf->len = DEFAULT_MSG_LEN;

    inet_ntop(their_addr->ss_family, get_in_addr((struct sockaddr *)their_addr), s, sizeof s);
    log_info("Accepted connection %d from %s", socket, s);
}

/**
 * Parses out a `message_s` from a `read_buffer_slice_s`. Assumes
 * that the slice contains a complete message.
 */
static message_s *parse_msg(data_buffer_slice_s slice)
{
    uint32_t msg_size = *((uint32_t *)slice.start);
    message_s *rv = malloc(sizeof(message_s) + msg_size);
    rv->msg_size = msg_size;

    size_t offset = sizeof(uint32_t);
    rv->type = *((uint8_t *)(slice.start + offset));

    offset += sizeof(uint8_t);
    memcpy(&rv->topic, slice.start + offset, TOPIC_LEN);

    offset += TOPIC_LEN;
    memcpy(&rv->body, slice.start + offset, msg_size - offset);
    return rv;
}

/**
 * Writes a message out to a contiguous buffer ready for sending over the wire.
 */
static data_buffer_s *pack_msg(message_s *msg)
{
    data_buffer_s *rv = malloc(sizeof(data_buffer_s) + msg->msg_size);
    rv->len = msg->msg_size;
    memcpy(rv->buf, &msg->msg_size, sizeof(uint32_t));

    size_t offset = sizeof(uint32_t);
    memcpy(rv->buf + offset, &msg->type, sizeof(uint8_t));

    offset += sizeof(uint8_t);
    memcpy(rv->buf + offset, msg->topic, TOPIC_LEN);

    offset += TOPIC_LEN;
    memcpy(rv->buf + offset, msg->body, msg->msg_size - offset);
    return rv;
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

    log_info("Preparing to accept");
    io_uring_sqe_set_data(sqe, &conn->accept_op);
    io_uring_submit(server->ring);
}

/**
 * Helper function to prepare a recv call on the io uring.
 */
static void prepare_recv(memo_server_s *server, connection_s *conn, void *buf, size_t length)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(server->ring);

    conn->read_op.conn = conn;
    conn->read_op.state = CONN_READ;

    log_info("Preparing to read %ld bytes on client %d", length, conn->socket);
    io_uring_prep_recv(sqe, conn->socket, buf, length, 0);
    io_uring_sqe_set_data(sqe, &conn->read_op);
    io_uring_submit(server->ring);
}

/**
 * Enqueues a read request for the default message size worth of data from the
 * connection. This includes a message header and a bit of extra room for a message
 * body. If the whole message fails to fit within this block we will enqueue another
 * read for what remains.
 */
static void read_from_start(memo_server_s *server, connection_s *conn)
{
    conn->bytes_r = 0;
    prepare_recv(server, conn, conn->read_buf->buf, DEFAULT_MSG_LEN); // TODO: should DEFAULT_MSG_LEN be buf->len?
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
 * Helper function to prepare a send over the io uring.
 */
static void prepare_write(memo_server_s *server, connection_s *dest, void *buf, size_t length)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(server->ring);

    dest->write_op.conn = dest;
    dest->write_op.state = CONN_WRITE;

    if (get_env_partial_writes())
    {
        length = length > PARTIAL_MSG_LEN ? PARTIAL_MSG_LEN : length;
        log_info("Preparing partial write %ld bytes to client %d", length, dest->socket);
    }
    else
    {
        log_info("Preparing to write %ld bytes to client %d", length, dest->socket);
    }

    io_uring_prep_write(sqe, dest->socket, buf, length, 0);
    io_uring_sqe_set_data(sqe, &dest->write_op);
    io_uring_submit(server->ring);
}

/**
 * Finds the subscription_s for the given topic.
 *
 * @returns The subscription_s if found, NULL otherwise.
 */
static subscription_s *find_subscription(memo_server_s *server, const char *topic)
{
    subscription_s *sub;
    for (sub = server->subscriptions; sub; sub = sub->next)
    {
	if (!memcmp(sub->topic, topic, TOPIC_LEN))
	{
	    break;
	}
    }

    return sub;
}

/**
 * Adds a new subscription to the server. A new subscription_s object
 * is created if necessary and the connection registered as being interested
 * in the topic. When messages appear on the topic they will be sent to
 * each connection on the subscription.
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
    data_buffer_s *data = msg_queue_pop(conn->mq);
    if (data == NULL)
        return;

    conn->write_buf = data;
    conn->bytes_w = 0;
    prepare_write(server, conn, conn->write_buf->buf, conn->write_buf->len);
}

/**
 * Publishes a message to any interested subscribers.
 *
 * @param `server` the memo server instance
 * @param `msg`    the message to send to any interested subscribers
 */
static void publish_msg(memo_server_s *server, message_s *msg)
{
    subscription_s *sub = find_subscription(server, msg->topic);
    if (!sub)
    {
        log_debug("No subscribers found for '%s', message dropped", msg->topic);
        return;
    }

    data_buffer_s *data = pack_msg(msg);
    for (connection_s *s = sub->connections; s; s = s->next_s)
    {
        if (!msg_queue_push(s->mq, data))
        {
            log_warn("Message queue full on client %d. Message dropped.", s->socket);
            continue;
        }

        if (s->write_buf == NULL)
            dequeue_publish(server, s);
    }
}

/**
 * Processes a fully read message from a client connection.
 */
static void process_msg(memo_server_s *server, connection_s *conn, message_s *msg)
{
    print_message(msg);
    switch (msg->type)
    {
    case OP_SUBSCRIBE:
        register_subscription(server, conn, msg->topic);
        break;
    case OP_PUBLISH:
        publish_msg(server, msg);
        break;
    }

    //free(conn->message);
    //conn->message = NULL;
    //conn->msg_size = 0;
}

/**
 * Parses and processes any complete messages in the buffer.
 *
 * @returns the slice of data that contains an incomplete message
 */
static data_buffer_slice_s try_process_messages(memo_server_s *server, connection_s *conn, data_buffer_slice_s slice)
{
    if (slice_len(slice) < MSG_HEADER_LEN || slice_len(slice) < msg_len(slice.start))
        return slice;

    message_s *msg = parse_msg(slice);
    process_msg(server, conn, msg);

    data_buffer_slice_s next =
    {
        .start = slice.start + msg->msg_size,
        .end = slice.end
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
 * if it is (or the size in unknown).
 *
 * @param `conn`   the connection, contains the buffer populated by `recv`
 * @param `slice`  points to the unhandled data
 *
 * @returns the amount of data to request in the next `recv` call
 */
static size_t prepare_next_read(connection_s *conn, data_buffer_slice_s slice)
{
    ptrdiff_t unhandled_len = slice_len(slice);

    // Scenario 1: we're gonna need a bigger boat
    if (unhandled_len > MSG_HEADER_LEN && msg_len(slice.start) > conn->read_buf->len)
    {
        size_t new_buf_len = max(msg_len(slice.start), DEFAULT_MSG_LEN);
        data_buffer_s *new_buf = calloc(1, sizeof(data_buffer_s) + new_buf_len);
        new_buf->len = new_buf_len;
        memcpy(new_buf->buf, slice.start, msg_len(slice.start));
        free(conn->read_buf);
        conn->read_buf = new_buf;
        conn->bytes_r = unhandled_len;
        return msg_len(conn->read_buf->buf) - unhandled_len;
    }

    // Scenarios 2 and 3
    if (slice.start > conn->read_buf->buf)
    {
        conn->bytes_r = unhandled_len;
        memmove(conn->read_buf->buf, slice.start, unhandled_len);
    }

    return conn->read_buf->len - unhandled_len;
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
static size_t handle_read_response(memo_server_s *server, connection_s *conn, size_t bytes_read)
{
    conn->bytes_r += bytes_read;
    data_buffer_slice_s slice =
    {
        .start = conn->read_buf->buf,
        .end = conn->read_buf->buf + conn->bytes_r
    };

    data_buffer_slice_s remaining = try_process_messages(server, conn, slice);
    return slice_len(remaining) ? prepare_next_read(conn, remaining) : 0;
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
static size_t handle_write_response(connection_s *conn, size_t bytes_written)
{
    conn->bytes_w += bytes_written;
    if (conn->bytes_w == conn->write_buf->len)
    {
        log_info("Write %d completed on client %d", conn->bytes_w, conn->socket);
        conn->write_buf = NULL;
        conn->bytes_w = 0;
        return 0;
    }

    return conn->write_buf->len - conn->bytes_w;
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
    
    return svr;
}

int memo_server_process(memo_server_s *server)
{
    struct io_uring_cqe *cqe;
    struct sockaddr_storage their_addr;
    socklen_t their_addr_len = sizeof(their_addr);

    prepare_accept(server, &their_addr, &their_addr_len);

    while (1)
    {
        int rv = io_uring_wait_cqe(server->ring, &cqe);
        if (rv < 0)
        {
            perror("io_uring_wait_cqe");
            return 1;
        }

        op_context_s *ctx = (op_context_s *)cqe->user_data;
        connection_s *conn = ctx->conn;
        if (cqe->res < 0)
        {
            log_error("Async request failed: '%s' for socket: %d",
                      strerror(-cqe->res), conn->socket);
            return 1;
        }

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
        case CONN_ACCEPT:
            initialise_connection(conn, cqe->res, &their_addr);
            prepare_accept(server, &their_addr, &their_addr_len);
            read_from_start(server, conn);
            break;
        case CONN_READ:
            {
                size_t next_read = handle_read_response(server, conn, cqe->res);
                if (next_read > 0)
                    prepare_recv(server, conn, conn->read_buf->buf + conn->read_buf->len - next_read, next_read);
                else
                    read_from_start(server, conn);
                break;
            }
        case CONN_WRITE:
            {
                uint32_t next_write = handle_write_response(conn, cqe->res);
                if (next_write)
                    prepare_write(server, conn, conn->write_buf->buf + conn->bytes_w, next_write);
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
        free_subscription(ptr);
    }

    for (connection_s *ptr = server->connections; ptr; ptr = server->connections)
    {
        if (ptr)
            server->connections = ptr->next_r;
        free_connection(ptr);
    }

    if (server->ring != NULL)
        io_uring_queue_exit(server->ring);
    
    close(server->listener);
    free(server);
}
