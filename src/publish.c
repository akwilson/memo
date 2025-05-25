#include <sys/stat.h>
#include "memo_int.h"

typedef struct _MemoPublisher
{
    int   connection;
    char* hostname;
    char* port;
} MemoPublisher;

static int mk_msg(int len, char* msg, char* topic, char** buf)
{
    uint32_t slen;
    int      topic_len = strlen(topic);

    slen = htonl(len + topic_len + 1);

    *buf = (char*)malloc(HEADER_LEN + topic_len + 1 + len);
    memcpy(*buf, &slen, HEADER_LEN);
    memcpy(*buf + HEADER_LEN, topic, topic_len);
    memcpy(*buf + HEADER_LEN + topic_len, ":", 1);
    memcpy(*buf + HEADER_LEN + topic_len + 1, msg, len);
    return HEADER_LEN + topic_len + 1 + len;
}

// Waits for an acknowledgement response from the server to indicate
// that the message was received by the server.
static int await_ack(MemoPublisher* publisher)
{
    int  rcvd;
    char ack_buf[16];

    switch (rcvd = recv(publisher->connection, ack_buf, 16, 0))
    {
        case 0:
            fprintf(stderr, "Connection closed\n");
            break;
        case -1:
            perror("Error: receiving P_ACK");
            break;
        default:
            ack_buf[rcvd] = 0;
            if (strcmp(ack_buf, "P_ACK"))
            {
                fprintf(stderr, "Error: bad message published: %s\n", ack_buf);
                return 0;
            }
            printf("Acknowledgement received\n");
            break;
    }

    return (rcvd > 0) ? rcvd : 0;
}

void memo_free_publisher(MemoPublisher* pubs)
{
    close(pubs->connection);
    free(pubs->hostname);
    free(pubs->port);
    free(pubs);
}

// Establishes a new publisher connection to a Memo server listening on the given host / port.
void* memo_connect_publisher(char* host, char* port)
{
    int sockfd;
    if ((sockfd = connect_client(host, port, 0)) == -1)
        return 0;

    MemoPublisher* pubs = (MemoPublisher*)malloc(sizeof(MemoPublisher));
    pubs->connection = sockfd;
    pubs->hostname = strdup(host);
    pubs->port = strdup(port);

    return pubs;
}

// Publishes a message on the given topic to the connected Memo server.
int memo_publish(MemoPublisher* publisher, char* topic, char* msg, int len)
{
    int   sent = 0;
    int   rv = 0;
    char* msg_buf;
    int   tot_len = mk_msg(len, msg, topic, &msg_buf);

    printf("Sending %d bytes\n", tot_len);

    do
    {
        rv = send(publisher->connection, msg_buf + sent, tot_len - sent, 0);
        printf("Sent\n");
        if (rv == -1)
        {
            perror("Error: sending");
            return 0;
        }
        sent += rv;
    } while (sent < tot_len);

    return (await_ack(publisher)) ? sent : 0;
}
