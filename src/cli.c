#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "memo.h"

#define INIT_BUFFER_LEN 4096
#define shift(argc, argv) (assert((argc) > 0), --(argc), *(argv)++)

const char *hostname, *port;

static void usage(const char *msg)
{
    fprintf(stderr, "usage: memo [-h hostname] [-p port] <command> [<args>]\n\n");
    fprintf(stderr, "Commands are:\n");
    fprintf(stderr, "    sub - Subscribe to one or more topics and display messages received\n");
    fprintf(stderr, "    pub - Publish a message to a topic\n");
    if (msg)
    {
        fprintf(stderr, "\nError: %s\n", msg);
    }

    exit(1);
}

/**
 * Gets the hostname and port from either the command line or environment
 * variables. Command line takes precedence.
 */
static void get_hostname_port(int *argc, char **argv[])
{
    while (*argc > 0)
    {
        const char *arg = shift(*argc, *argv);
        if (strcmp(arg, "-h") == 0)
        {
            if (*argc == 0) usage("specify hostname after -h");
            hostname = shift(*argc, *argv);
        }
        else if (strcmp(arg, "-p") == 0)
        {
            if (*argc == 0) usage("specify port after -p");
            port = shift(*argc, *argv);
        }
        else
        {
            // Unknown arg — push back and stop parsing connection args
            --(*argv);
            ++(*argc);
            break;
        }
    }

    if (!hostname) hostname = getenv("MEMO_HOST");
    if (!port) port = getenv("MEMO_PORT");

    if (!hostname || !port)
        usage("hostname or port not specified");
}

static const char *read_stdin_all()
{
    size_t batch = INIT_BUFFER_LEN;
    size_t length = 0;
    char   *buffer = malloc(batch);

    size_t n;
    while ((n = fread(buffer + length, 1, batch - length, stdin)) > 0)
    {
        length += n;
        if (length == batch)
        {
            batch *= 2;
            buffer = realloc(buffer, batch);
        }
    }

    buffer[length] = '\0';
    return buffer;
}

static void handler(memo_client_s *mc, memo_msg_s msg)
{
    (void)mc; // unused
    printf("%s: %.*s\n", msg.topic, (int)msg.body_len, (char *)msg.body);
    memo_msg_free(msg);
}

static int subscriber(int argc, char *argv[])
{
    shift(argc, argv);
    if (argc == 0)
    {
        usage("sub <topics>");
    }

    memo_client_s *mc = memo_client_init(hostname, port);
    if (mc == NULL)
        return 1;

    while (argc)
    {
        const char *next_arg = shift(argc, argv);
        if (memo_client_sub(mc, next_arg, handler))
            return 1;
        printf("Subscribed to '%s'\n", next_arg);
    }

    printf("Listening for messages from Memo...\n");
    memo_client_listen(mc);
    memo_client_free(mc);

    return 0;
}

static int publisher(int argc, char *argv[])
{
    shift(argc, argv);
    if (argc < 1 || argc > 2)
        usage("pub <topic> [message]");

    const char *topic = shift(argc, argv);
    const char *msg = (argc == 1) ? shift(argc, argv) : read_stdin_all();
    size_t len = strlen(msg);

    memo_client_s *mc = memo_client_init(hostname, port);
    if (mc == NULL)
        return 1;

    if (memo_client_pub(mc, topic, (const uint8_t *)msg, len))
        return 1;

    memo_client_free(mc);
    return 0;
}

int main(int argc, char *argv[])
{
    shift(argc, argv);
    if (!argc) usage(NULL);

    get_hostname_port(&argc, &argv);
    if (!argc) usage("no command specified");

    if (!strncmp(*argv, "sub", 3))
    {
        return subscriber(argc, argv);
    }
    else if (!strncmp(*argv, "pub", 3))
    {
        return publisher(argc, argv);
    }

    usage("invalid command specified");
    return 0;
}
