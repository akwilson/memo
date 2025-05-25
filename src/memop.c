#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "memo.h"

static char* read_file(char* path)
{
    FILE*       file;
    struct stat buf;
    char*       fd;

    if (stat(path, &buf))
    {
        return 0;
    }

    fd = (char*)malloc(buf.st_size + 1);

    if ((file = fopen(path, "r")) == 0)
    {
        return 0;
    }

    fread(fd, buf.st_size, 1, file);
    return fd;
}

// Entry point for memop -- publish messages to the Memo server.
int main(int argc, char* argv[])
{
    void* publisher;
    int   sent;
    char* data;

    if (argc < 5)
    {
        fprintf(stderr,"Usage: memop hostname port topic message\n");
        return 1;
    }

    if (!strcmp(argv[4], "-f"))
    {
        if ((data = read_file(argv[5])) == 0)
        {
            fprintf(stderr, "Error: unable to open file '%s'\n", argv[5]);
            return 1;
        }
    }
    else
    {
        data = argv[4];
    }

    if ((publisher = memo_connect_publisher(argv[1], argv[2])) == 0)
    {
        return 1;
    }

    if (sent = memo_publish(publisher, argv[3], data, strlen(data)))
    {
        printf("memop: sent topic '%s' msg '%s' len=%d\n", argv[3], data, sent);
    }

    memo_free_publisher(publisher);
    return 0;
}
