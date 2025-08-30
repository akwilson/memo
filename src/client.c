#include <pwd.h>
#include <assert.h>
#include "memo_int.h"

/**
 * Maps a topic to a message handler callback.
 */
typedef struct topic_handler
{
    char                 topic[TOPIC_LEN];
    memo_callback        callback;
    struct topic_handler *next;
} topic_handler_s;

struct memo_client
{
    int             socket;
    memo_alloc_fn   allocator;
    topic_handler_s *handlers;
};

/**
 * Writes a message to a file descriptior representing a Memo server. Loops if
 * neccessary until the whole message is sent.
 *
 * @param `socket` the socket representing the connection to the Memo server
 * @param `slice`  the message to be sent
 *
 * @returns the number of bytes actually sent
 */
static int send_msg(int socket, data_slice_s slice)
{
    uint32_t sent = 0;
    do
    {
        int rv = send(socket, slice.ptr + sent, slice.len - sent, 0);
        if (rv == -1)
            break;
        sent += rv;
    } while (sent < slice.len);

    return sent;
}

// Sends a login message to the server to register a new connection. If the
// client is a subscriber the topic should be not null.
/*
static int server_login(int sockfd, char* topic)
{
    char data[LOGIN_LEN];
    int len;
    struct passwd* pw;
    uint32_t type = topic ? htonl(CL_SUBSCRIBER) : htonl(CL_PUBLISHER);

    if ((pw = getpwuid(getuid())) == 0)
    {
        perror("Error: server_login");
        return 1;
    }

    memcpy(data, &type, sizeof(uint32_t));
    if (topic)
        sprintf(data + sizeof(uint32_t), "%s|%s", pw->pw_name, topic);
    else
        strcpy(data + sizeof(uint32_t), pw->pw_name);
    len = LOGIN_LEN;

    return send_msg(sockfd, data, &len);
}
*/

/**
 * Establishes a new client connection to the Memo server.
 */
static int connect_client(const char *host, const char *port)
{
    int             sockfd;
    struct addrinfo hints;
    struct addrinfo *servinfo;
    struct addrinfo *p;
    int             rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "Error: getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) != -1)
        {
            // Connected successfully
            break;
        }

        close(sockfd);
    }

    if (p == NULL)
    {
        fprintf(stderr, "Error: unable to connect to Memo server at '%s:%s'\n", host, port);
        return -1;
    }

    freeaddrinfo(servinfo);
    return sockfd;
}

/**
 * Check that the data passed in from the user is valid.
 */
static int verify_memo_params(memo_client_s *mc, const char *topic)
{
    if (mc == NULL || mc->socket == 0)
    {
        fprintf(stderr, "Error: attempt to send message to unconnected client\n");
        return 1;
    }

    if (strlen(topic) > TOPIC_LEN)
    {
        fprintf(stderr, "Topic length exceeds maximum of %d bytes\n", TOPIC_LEN);
        return 1;
    }

    return 0;
}

static data_slice_s pack_client_msg(msg_type_e type, const char *topic, const uint8_t *msg, size_t len)
{
    uint32_t msg_len = len + MSG_HEADER_LEN;
    uint8_t  *buf = calloc(1, msg_len);

    memcpy(buf, &msg_len, sizeof(uint32_t));

    size_t offset = sizeof(uint32_t);
    memcpy(buf + offset, &type, sizeof(uint8_t));

    offset += sizeof(uint8_t);
    int topic_len = strlen(topic);
    memcpy(buf + offset, topic, topic_len);

    if (msg != NULL)
    {
        offset += TOPIC_LEN;
        memcpy(buf + offset, msg, msg_len - offset);
    }

    data_slice_s slice =
    {
        .len = msg_len,
        .ptr = buf
    };

    return slice;
}

static topic_handler_s *lookup_handler(memo_client_s *mc, const char *topic)
{
    topic_handler_s *th;
    for (th = mc->handlers; th; th = th->next)
    {
        if (!memcmp(th->topic, topic, TOPIC_LEN))
            break;
    }

    return th;
}

memo_client_s *memo_client_init(const char* hostname, const char *port)
{
    int socket = connect_client(hostname, port);
    if (socket == -1)
        return NULL;

    memo_client_s *rv = malloc(sizeof(memo_client_s));
    rv->socket = socket;
    rv->allocator = malloc;
    rv->handlers = NULL;
    return rv;
}

void memo_client_set_allocator(memo_client_s *mc, memo_alloc_fn alloc)
{
    mc->allocator = alloc;
}

int memo_client_pub(memo_client_s *mc, const char *topic, const uint8_t *msg, size_t len)
{
    if (verify_memo_params(mc, topic))
        return 1;

    data_slice_s slice = pack_client_msg(OP_PUBLISH, topic, msg, len);
    int sent = send_msg(mc->socket, slice);
    return slice.len - sent;
}

int memo_client_sub(memo_client_s *mc, const char *topic, memo_callback callback)
{
    if (verify_memo_params(mc, topic))
        return 1;

    data_slice_s slice = pack_client_msg(OP_SUBSCRIBE, topic, NULL, 0);
    int sent = send_msg(mc->socket, slice);

    topic_handler_s *th = calloc(1, sizeof(topic_handler_s));
    strcpy(th->topic, topic); // TODO: danger
    th->callback = callback;
    th->next = mc->handlers;
    mc->handlers = th;

    return slice.len - sent;
}

void memo_client_listen(memo_client_s *mc)
{
    uint32_t msg_len;
    uint32_t received;
    int      num_bytes;

    while (1)
    {
        num_bytes = recv(mc->socket, &msg_len, sizeof(uint32_t), 0);
        if (num_bytes == 0)
            goto DISCONNECT;

        if (num_bytes < 0)
            goto ERROR;

        uint8_t *raw_data = mc->allocator(msg_len);
        memcpy(raw_data, &msg_len, num_bytes); 
        received = num_bytes;

        do
        {
            num_bytes = recv(mc->socket, raw_data + received, msg_len - received, 0);
            if (num_bytes == 0)
                goto DISCONNECT;

            if (num_bytes < 0)
                goto ERROR;

            received += num_bytes;
        } while (received < msg_len);

        memo_msg_s msg_view =
        {
            .msg_len = msg_len,
            .topic = (const char *)(raw_data + sizeof(uint32_t) + sizeof(uint8_t)),
            .body = raw_data + MSG_HEADER_LEN,
            .body_len = msg_len - MSG_HEADER_LEN,
            ._raw_data = raw_data,
            ._header = NULL
        };

        topic_handler_s *handler = lookup_handler(mc, msg_view.topic);
        assert(handler != 0);
        handler->callback(mc, msg_view);
    }

 DISCONNECT:
    fprintf(stderr, "Connection to Memo server lost\n");
    return;

 ERROR:
    perror("recv");
    return;
}

void memo_msg_free(memo_msg_s msg)
{
    free(msg._raw_data);
}

void memo_client_free(memo_client_s *mc)
{
    close(mc->socket);

    for (topic_handler_s *ptr = mc->handlers; ptr; ptr = mc->handlers)
    {
        if (ptr)
            mc->handlers = ptr->next;
        free(ptr);
    }
    
    free(mc);
}
