#include <memo_int.h>

typedef struct _MemoSubscriber
{
    int   connection;
    char* hostname;
    char* port;
    char* topic;
} MemoSubscriber;

void memo_free_subscriber(MemoSubscriber* subs)
{
    close(subs->connection);
    free(subs->hostname);
    free(subs->port);
    free(subs->topic);
    free(subs);
}

void* memo_connect_subscriber(char* host, char* port, char* topic)
{
    int sockfd;
    if ((sockfd = connect_client(host, port, topic)) == -1)
        return 0;

    MemoSubscriber* subs = (MemoSubscriber*)malloc(sizeof(MemoSubscriber));
    subs->connection = sockfd;
    subs->hostname = strdup(host);
    subs->port = strdup(port);
    subs->topic = strdup(topic);

    return subs;
}

int memo_receive_msg(MemoSubscriber* subscriber, char** msg, int* len)
{
    uint32_t msg_len_u;
    int      msg_len;
    int      numbytes;
    int      received = 0;

    if ((numbytes = recv(subscriber->connection, &msg_len_u, HEADER_LEN, 0)) == -1)
    {
        perror("receive_msg");
        return 1;
    }

    if (numbytes > 0)
    {
        msg_len = ntohl(msg_len_u);
        *msg = (char*)malloc(msg_len + 1);  // leave room for the null terminator

        do
        {
            if ((numbytes = recv(subscriber->connection, *msg + received, msg_len - received, 0)) == -1)
            {
                perror("receive_msg");
                return 1;
            }
            received += numbytes;
            printf("client: read %d bytes\n", received);
        } while (received < msg_len);

        (*msg)[msg_len] = 0;
        *len = msg_len;
    }
    else
    {
        fprintf(stderr, "Connection to server lost\n");
        return 1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    MemoSubscriber* subscriber;
    int             len;
    char*           msg;

    if (argc != 4)
    {
        fprintf(stderr,"usage: memos hostname port topic\n");
        return 1;
    }

    if ((subscriber = memo_connect_subscriber(argv[1], argv[2], argv[3])) == 0)
        return 1;

    while (memo_receive_msg(subscriber, &msg, &len) == 0)
    {
        if (strcmp(msg, "quit") == 0)
        {
            printf("memos: quit command received.  Exiting...\n");
            break;
        }
        printf("client: received '%s' len=%d\n", msg, len);
    }

    memo_free_subscriber(subscriber);

    return 0;
}
