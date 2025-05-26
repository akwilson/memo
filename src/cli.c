#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "memo_int.h"

#define shift(argc, argv) (assert((argc) > 0), --(argc), *(argv)++)

static void usage(const char *msg)
{
    fprintf(stderr, "usage: memo [-v] [-h] <command> [<args>]\n\n");
    fprintf(stderr, "Commands are:\n");
    fprintf(stderr, "    sub - Subscribe to one or more topics and display messages received\n");
    fprintf(stderr, "    pub - Publish a message to a topic\n");
    if (msg)
    {
        fprintf(stderr, "\nError: %s\n", msg);
    }

    exit(1);
}

/*
static void handler(memo_client_s *mc, const char *topic, const char *msg, size_t len)
{
    printf("%s: %s\n", topic, msg);
}
*/

static int subscriber(int argc, char *argv[])
{
    const char *next_arg = shift(argc, argv);
    // const char *hostname = shift(argc, argv);
    // const char *port = shift(argc, argv);

    if (argc == 0)
    {
        usage("sub: [topics]");
    }

    /*
    memo_client_s *mc = memo_client_init(hostname, port);
    if (mc == NULL)
        return 1;
    */

    while (argc)
    {
        next_arg = shift(argc, argv);
        printf("subscribing to %s\n", next_arg);
        // memo_client_sub(mc, next_arg, handler);
    }

    // memo_client_listen(mc);
    // memo_client_free(mc);

    return 0;
}

static int publisher(int argc, char *argv[])
{
    shift(argc, argv);
    if (argc != 4)
        usage("pub: <hostname> <port> <topic> <message>");

    const char *hostname = shift(argc, argv);
    const char *port = shift(argc, argv);
    const char *topic = shift(argc, argv);
    const char *msg = shift(argc, argv);
    size_t len = strlen(msg);

    memo_client_s *mc = memo_client_init(hostname, port);
    if (mc == NULL)
        return 1;

    if (memo_client_pub(mc, topic, msg, len))
        return 1;

    memo_client_free(mc);
    return 0;
}

int main(int argc, char *argv[])
{
    shift(argc, argv);
    if (!argc)
        usage(NULL);

    if (!strncmp(*argv, "sub", 3))
    {
        return subscriber(argc, argv);
    }
    else if (!strncmp(*argv, "pub", 3))
    {
        return publisher(argc, argv);
    }

    usage("Invalid command specified");
    return 0;
}
