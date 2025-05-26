#include <stdio.h>
#include "memo.h"

/**
 * Entry point for memod -- the Memo server. Initialises a Memo server and processes messages.
 */
int main(int argc, char *argv[])
{
    memo_server_s *server;

    if (argc != 2)
    {
        fprintf(stderr, "usage: memod port\n");
        return 1;
    }

    if ((server = memo_server_init(argv[1])) == 0)
    {
        return 1;
    }

    int rv = memo_server_process(server);
    memo_server_free(server);

    return rv;
}
