#include <stdio.h>
#include "memo.h"

int main(int argc, char* argv[])
{
    void* server;
    int   rv;

    if (argc != 2)
    {
        fprintf(stderr, "usage: memod port\n");
        return 1;
    }


    if ((server = memo_start_server(argv[1])) == 0)
    {
        return 1;
    }

    printf("memod: waiting for connections...\n");

    rv = memo_process_server(server);
    memo_free_server(server);

    return rv;
}
