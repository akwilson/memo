#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "memo.h"

#define shift(argc, argv) (assert((argc) > 0), --(argc), *(argv)++)

static void usage()
{
    fprintf(stderr, "usage: memo [-v] [-h] <command> [<args>]\n\n");
    fprintf(stderr, "Commands are:\n");
    fprintf(stderr, "    sub - Subscribe to one or more topics and display messages received\n");
    fprintf(stderr, "    pub - Publish a message to a topic\n");
    exit(1);
}

static int subscriber(int argc, char *argv[])
{
    const char *next_arg = shift(argc, argv);
    printf("subscriber\n");
    while (argc)
    {
        next_arg = shift(argc, argv);
        printf("%s\n", next_arg);
    }

    return 0;
}

static int publisher(int argc, char *argv[])
{
    const char *next_arg = shift(argc, argv);
    printf("publisher\n");
    while (argc)
    {
        next_arg = shift(argc, argv);
        printf("%s\n", next_arg);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    shift(argc, argv);
    if (!argc)
        usage();

    if (!strncmp(*argv, "sub", 3))
    {
        return subscriber(argc, argv);
    }
    else if (!strncmp(*argv, "pub", 3))
    {
        return publisher(argc, argv);
    }

    usage();
    return 0;
}
