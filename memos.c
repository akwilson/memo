#include <stdio.h>
#include <string.h>
#include "memo.h"

// Entry point for memos -- a subscriber to the Memo server.
int main(int argc, char* argv[])
{
    void* subscriber;
    int   len;
    char* msg;

    if (argc != 4)
    {
        fprintf(stderr,"usage: memos hostname port topic\n");
        return 1;
    }

    if ((subscriber = memo_connect_subscriber(argv[1], argv[2], argv[3])) == 0)
    {
        return 1;
    }

    while (memo_subscribe(subscriber, &msg, &len) == 0)
    {
        if (strcmp(msg, "quit") == 0)
        {
            printf("memos: quit command received.  Exiting...\n");
            break;
        }

        printf("memos: received '%s' len=%d\n", msg, len);
    }

    memo_free_subscriber(subscriber);
    return 0;
}
