#include "memo_int.h"

#define BACKLOG 10                  // how many pending connections queue will hold
#define MAX(x,y) ((x) > (y) ? (x) : (y))

// TODO map of topic->subscribers; map of fd->publisher & fd->subscriber
// TODO remove clients from the list when they close...

// Message to be sent to subscribers
typedef struct
{
    char* msg;     // encoded message
    char  topic[32];
    int   tot_len; // length of encoded message
    int   senders; // number of MessagePtrs trying to send
} MessageData;

// Linked list of outstanding MessageData objects to be transferred
typedef struct _MessagePtr
{
    MessageData*        data;
    int                 transferred; // number of bytes transferred so far for this client
    struct _MessagePtr* next;
} MessagePtr;

// A connected subscriber
typedef struct _Subscriber
{
    int                 fd;
    struct sockaddr     address;
    char                topic[16];
    char                username[16];
    MessagePtr*         cur_msg;      // outstanding messages
    MessagePtr*         last_msg;
    struct _Subscriber* next;
} Subscriber;

// A connected publisher
typedef struct _Publisher
{
    int                fd;
    struct sockaddr    address;
    char               username[16];
    MessagePtr*        cur_msg;
    struct _Publisher* next;
} Publisher;

// The server struct with lists of subscribers and publishers and the listening fd
typedef struct
{
    int         listener;
    Subscriber* subscribers;
    Publisher*  publishers;
} MemoServer;

// Gets the IP address, either IPv4 or IPv6
static void* get_in_addr(struct sockaddr* sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// Reads the login information from a newly connected client. Returns a value to indicate
// if the client is a publisher or a subscriber. The login_data contains the client's
// username and, for subscribers, the topic.
static int get_login(int fd, char** login_data)
{
    // for now, assumes that recv() reads the whole login message
    // should probably feed back to select() instead...
    static char data[LOGIN_LEN];
    char*       delim;
    int         numbytes;
    uint32_t*   type;

    if ((numbytes = recv(fd, data, LOGIN_LEN, 0)) == -1)
    {
        perror("get_login");
        return 1;
    }
    *(data + numbytes) = 0;

    type = (uint32_t*)data;

    *login_data = (char*)(type + 1);

    return ntohl(*type);
}

// Reads the topic from a message sent by a publisher.
static void parse_topic(MessageData* md)
{
    // get the topic.  TODO do this properly
    char* ptr;
    char* ts = md->msg + 4;
    int   tl;

    ptr = strchr(ts, ':');
    tl = ptr - ts;
    memcpy(md->topic, ts, tl);
    *(md->topic + tl) = 0;
}

// Sets up a new message to be transferred.
static MessagePtr* init_message(Publisher* ptr, uint32_t msg_len_u)
{
    MessagePtr* mp = ptr->cur_msg;
    int         msg_len;

    msg_len = ntohl(msg_len_u);

    if (mp == 0)
    {
        mp = (MessagePtr*)malloc(sizeof(MessagePtr));
        ptr->cur_msg = mp;
    }

    mp->data = (MessageData*)malloc(sizeof(MessageData));
    mp->data->senders = 0;
    mp->data->msg = (char*)malloc(msg_len + HEADER_LEN);
    memcpy(mp->data->msg, &msg_len_u, HEADER_LEN);
    mp->data->tot_len = msg_len + HEADER_LEN;
    mp->transferred = HEADER_LEN;
    return mp;
}

// Reads a chunk of message from a publisher. Populates msg_data.
// Returns 1 to indicate that there is more still to be transferred. 0 indicates
// that message transfer is complete. -1 indicates an error.
static int new_message(Publisher* pub, MessageData** msg_data)
{
    MessagePtr* mptr = pub->cur_msg;
    int         numbytes;

    *msg_data = 0;

    // Start of published message
    if ((mptr == 0) || (mptr->data == 0))
    {
        uint32_t msg_len_u;

        switch (numbytes = recv(pub->fd, &msg_len_u, HEADER_LEN, 0))
        {
        case -1:
            perror("new_message read_1");
            return -1;
        case 0:
            fprintf(stderr, "Connection to publisher closed\n");
            return -1;
        default:
            mptr = init_message(pub, msg_len_u);
            break;
        }
    }

    // The rest of the message
    switch (numbytes = recv(pub->fd, mptr->data->msg + mptr->transferred,
                         mptr->data->tot_len - mptr->transferred, 0))
    {
    case -1:
        perror("receive_msg read_2");
        return -1;
    case 0:
        fprintf(stderr, "Connection to publisher closed\n");
        return -1;
    default:
        mptr->transferred += numbytes;
        printf("server: publish read %d bytes\n", mptr->transferred);

        if (mptr->transferred < mptr->data->tot_len)
        {
            return 1; // More data to come
        }
        else
        {
            parse_topic(mptr->data);
            pub->cur_msg = 0;
            *msg_data = mptr->data;
        }
        break;
    }

    return 0;
}

// Sends an acknowledgement message to the publisher to indicate
// that the message was successfully sent.
static int send_ack(Publisher* pub)
{
    if ((send(pub->fd, "P_ACK", 5, 0)) == -1)
    {
        perror("send_ack");
        return 1;
    }
    return 0;
}

// Sets up a new client connection, publisher or subscriber.
// Returns 0 if in error, or a value to indicate if the client is a subscriber or publisher.
static int new_client(MemoServer* server, int new_fd)
{
    struct sockaddr addr;
    socklen_t       sin_size = sizeof(addr);
    char*           login_data;
    char*           delim;

    if (getpeername(new_fd, &addr, &sin_size))
    {
        perror("new_subscriber");
        return 0;
    }
    fcntl(new_fd, F_SETFL, O_NONBLOCK);

    if (get_login(new_fd, &login_data) == CL_SUBSCRIBER)
    {
        Subscriber* subs = (Subscriber*)malloc(sizeof(Subscriber));
        subs->next = server->subscribers;
        server->subscribers = subs;

        subs->fd = new_fd;

        delim = strchr(login_data, '|');
        *delim++ = 0;
        strcpy(subs->username, login_data);
        strcpy(subs->topic, delim);

        subs->cur_msg = 0;
        subs->last_msg = 0;

        subs->address = addr;

        printf("server: subscriber login: username=%s topic=%s\n", subs->username, subs->topic);
        return CL_SUBSCRIBER;
    }
    else
    {
        Publisher* pubs = (Publisher*)malloc(sizeof(Publisher));
        pubs->next = server->publishers;
        server->publishers = pubs;

        pubs->cur_msg = 0;

        pubs->fd = new_fd;

        strcpy(pubs->username, login_data);

        pubs->address = addr;

        printf("server: publisher login: username=%s\n", pubs->username);
        return CL_PUBLISHER;
    }
}

static void free_message(MessageData* md)
{
    free(md->msg);
    free(md);
}

// Initialise a new MessagePtr, point it to the MessageData and add it to the
// tail of the Subscriber's MessagePtr list. A message is sent to the subscriber one block
// at a time; the subscriber's MessagePtr keeps track of how far through the message
// this subscriber has got.
static void prepare_send(Subscriber* subs, MessageData* md)
{
    MessagePtr* mptr = (MessagePtr*)malloc(sizeof(MessagePtr));

    md->senders++;

    mptr->transferred = 0;
    mptr->data = md;
    mptr->next = 0;

    if (subs->cur_msg == 0)
        subs->cur_msg = mptr;
    if (subs->last_msg)
        subs->last_msg->next = mptr;
    subs->last_msg = mptr;
}

// Returns the subscriber on the given file descriptor
static Subscriber* get_subscriber(MemoServer* server, int fd)
{
    Subscriber* ptr;
    for (ptr = server->subscribers; ptr; ptr = ptr->next)
    {
        if (ptr->fd == fd)
            return ptr;
    }
    return 0;
}

// Returns the publisher on the given file descriptor
static Publisher* get_publisher(MemoServer* server, int fd)
{
    Publisher* ptr;
    for (ptr = server->publishers; ptr; ptr = ptr->next)
    {
        if (ptr->fd == fd)
            return ptr;
    }
    return 0;
}

// Sends the next block of data for this subscriber. Moves the MessagePtr along to the next block.
static int send_msg(Subscriber* subs)
{
    int          bytes;
    MessagePtr*  cmsg = subs->cur_msg;
    MessageData* md = cmsg->data;

    bytes = send(subs->fd, md->msg + cmsg->transferred, md->tot_len - cmsg->transferred, 0);
    if (bytes == -1)
    {
        if (errno == EAGAIN)
        {
            printf("server: no send\n");
            return 1;
        }
        perror("send_msg");
        return -1;
    }

    cmsg->transferred += bytes;
    if (cmsg->transferred < md->tot_len)
    {
        printf("server: partial send. %d bytes sent\n", cmsg->transferred);
        return 1;
    }

    // Send complete.  Ready next message for this subscriber
    subs->cur_msg = subs->cur_msg->next;
    if (subs->cur_msg == 0)
    {
        // No messages left to send, clear last ptr
        subs->last_msg = 0;
    }

    free(cmsg);

    // If no one else needs this message, free it
    md->senders--;
    if (md->senders == 0)
    {
        free_message(md);
    }

    return 0;
}

// Receives a connection from a client. Gets its IP address
// and returns a new file descriptor for it.
static int handshake(MemoServer* server)
{
    int                     new_fd;
    struct sockaddr_storage their_addr;
    socklen_t               sin_size = sizeof(their_addr);
    char                    s[INET6_ADDRSTRLEN];

    new_fd = accept(server->listener, (struct sockaddr*)&their_addr, &sin_size);
    if (new_fd == -1)
        perror("handshake");

    inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr*)&their_addr), s, sizeof s);
    printf("server: got connection from %s fd=%d\n", s, new_fd);

    return new_fd;
}

static void free_publisher(Publisher* pub)
{
    close(pub->fd);
    if (pub->cur_msg)
        free(pub->cur_msg);
    free(pub);
}

// Removes publisher from the server when it has completed a publish request.
static void remove_publisher(MemoServer* server, Publisher* pub)
{
    Publisher** pub_ptr;
    for (pub_ptr = &(server->publishers); *pub_ptr; )
    {
        if (*pub_ptr == pub)
        {
            (*pub_ptr) = pub->next;
            free_publisher(pub);
            if ((*pub_ptr) == 0)
                break;
        }
        else
        {
            pub_ptr = &((*pub_ptr)->next);
        }
    }
}

// Frees up a disconnected subscriber.
static void free_subscriber(Subscriber* sub)
{
    MessagePtr* mp;

    close(sub->fd);
    for (mp = sub->cur_msg; mp; mp = sub->cur_msg)
    {
        if (mp)
            sub->cur_msg = mp->next;

        mp->data->senders--;
        if (mp->data->senders == 0)
            free_message(mp->data);
        free(mp);
    }

    free(sub);
}

// Frees up a Memo server and all of its publishers
void memo_free_server(MemoServer* server)
{
    Subscriber* ptr;

    for (ptr = server->subscribers; ptr; ptr = server->subscribers)
    {
        if (ptr)
            server->subscribers = ptr->next;
        free_subscriber(ptr);
    }

    close(server->listener);
    free(server);
}

// Initialises a new Memo server on the given port.
MemoServer* memo_start_server(char* port)
{
    int              sockfd;
    int              yes = 1;
    int              rv;
    struct addrinfo  hints;
    struct addrinfo* servinfo;
    struct addrinfo* p;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 0;
    }

    // Loop through all the results and bind to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            perror("setsockopt");
            return 0;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    if (p == NULL)
    {
        fprintf(stderr, "server: failed to bind\n");
        return 0;
    }

    freeaddrinfo(servinfo);

    if (listen(sockfd, BACKLOG) == -1)
    {
        perror("listen");
        return 0;
    }

    MemoServer* svr = (MemoServer*)malloc(sizeof(MemoServer));
    svr->listener = sockfd;
    svr->subscribers = 0;
    svr->publishers = 0;

    return svr;
}

// Processes publish and subscribe events for the Memo server.
int memo_process_server(MemoServer* server)
{
    int          fdmax = 0;
    int          fd;
    int          new_fd;
    fd_set       next_readfds;
    fd_set       next_writefds;
    int          next_fdm = 0;
    int          rv;
    Subscriber*  sub_ptr;
    Publisher*   pub_ptr;
    MessageData* msg_data;

    FD_ZERO(&next_readfds);
    FD_ZERO(&next_writefds);

    // The main event loop
    while (1)
    {
        fd_set readfds;
        fd_set writefds;

        readfds = next_readfds;
        writefds = next_writefds;
        fdmax = next_fdm;

        FD_SET(server->listener, &readfds);
        fdmax = MAX(fdmax, server->listener);

        if ((select(fdmax + 1, &readfds, &writefds, 0, 0)) == -1)
        {
            // TODO handle EAINT?
            perror("select");
            return 1;
        }

        FD_ZERO(&next_readfds);
        FD_ZERO(&next_writefds);

        for (fd = 0; fd <= fdmax; fd++)
        {
            // Process the read file descriptiors: messages from publishers and new connections
            if (FD_ISSET(fd, &readfds))
            {
                if (fd == server->listener) // Handle new connections
                {
                    if ((new_fd = handshake(server)) != -1)
                    {
                        // Prepare to receive login details
                        FD_SET(new_fd, &next_readfds);
                        next_fdm = MAX(next_fdm, new_fd);
                    }
                }
                else
                {
                    if (pub_ptr = get_publisher(server, fd))
                    {
                        if ((rv = new_message(pub_ptr, &msg_data)) == 0)
                        {
                            // Now that we have something to send, prepare the
                            // relevant subscribers for the next call to select()
                            for (sub_ptr = server->subscribers; sub_ptr; sub_ptr = sub_ptr->next)
                            {
                                if ((strcmp(sub_ptr->topic, msg_data->topic)) == 0)
                                {
                                    prepare_send(sub_ptr, msg_data);
                                    FD_SET(sub_ptr->fd, &next_writefds);
                                    next_fdm = MAX(next_fdm, sub_ptr->fd);
                                }
                            }
                            if (msg_data->senders == 0)
                                free_message(msg_data);

                            // Prepare to send ACK to Publisher
                            FD_SET(fd, &next_writefds);
                            next_fdm = MAX(next_fdm, fd);
                        }
                        if (rv == -1)
                            remove_publisher(server, pub_ptr);

                        break;
                    }

                    // If no publishers found, this must be a login message
                    if (pub_ptr == 0)
                        new_client(server, fd);
                }
            }

            // Process write descriptors: subscribers awaiting more data and publisher acknowledgements
            if (FD_ISSET(fd, &writefds))
            {
                if (sub_ptr = get_subscriber(server, fd))
                {
                    // Send message to subscriber
                    switch (send_msg(get_subscriber(server, fd)))
                    {
                    case 1:
                        FD_SET(fd, &next_writefds);
                        next_fdm = MAX(next_fdm, fd);
                        break;
                    case 0:
                        //close(fd);
                        break;
                    case -1:
                        // close fd and recycle subscriber.
                        break;
                    }
                }
                else
                {
                    // Send ACK to publisher
                    pub_ptr = get_publisher(server, fd);
                    if (send_ack(pub_ptr))
                    {
                        // close the fd and recycle the publisher. but for now...
                        fprintf(stderr, "Dodgy read error. Exiting...\n");
                        return 1;
                    }
                }
            }
        }

        // Add all publishers to the read file descriptor set
        for (pub_ptr = server->publishers; pub_ptr; pub_ptr = pub_ptr->next)
        {
            FD_SET(pub_ptr->fd, &next_readfds);
            next_fdm = MAX(next_fdm, pub_ptr->fd);
        }
    }

    return 0;
}
