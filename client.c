#include <pwd.h>
#include "memo_int.h"

// get sockaddr, IPv4 or IPv6
static void* get_in_addr(struct sockaddr* sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// Writes a message to a file descriptior representing a Memo server. Loops if
// neccessary until the whole message is sent.
// msg is the message to be sent, len the message length.
// Returns the total number of bytes actually sent.
static int send_msg(int socket, char* msg, int* len)
{
    int   sent = 0;
    int   rv = 0;
    char* msg_buf = msg;
    int   tot_len = *len;

    do
    {
        rv = send(socket, msg_buf + sent, tot_len - sent, 0);
        if (rv == -1)
            break;
        sent += rv;
    } while (sent < tot_len);

    *len = sent; // return total bytes sent
    return (rv == -1) ? 1 : 0;
}

// Sends a login message to the server to register a new connection. If the
// client is a subscriber the topic should be not null.
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

// Establishes a new client connection to the Memo server on host / port. If
// topic is not null a subscriber connection is made, otherwise a publisher.
int connect_client(char* host, char* port, char* topic)
{
    int              sockfd;
    struct addrinfo  hints;
    struct addrinfo* servinfo;
    struct addrinfo* p;
    int              rv;
    char             s[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "Error: getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // Loop through all the results and connect to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            perror("Error: connect socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            perror("Error: connect connect");
            close(sockfd);
            continue;
        }

        break;
    }

    if (p == NULL)
    {
        fprintf(stderr, "Error: failed to connect\n");
        return -1;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);
    printf("Connecting to %s\n", s);

    freeaddrinfo(servinfo); // all done with this structure

    if (server_login(sockfd, topic))
        return 0;

    return sockfd;
}
