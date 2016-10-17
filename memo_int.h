#ifndef MEMO_INT_H
#define MEMO_INT_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/fcntl.h>
#include <sys/wait.h>
#include <signal.h>

#define HEADER_LEN sizeof(uint32_t) // Header used to indicate size of msg to client
#define LOGIN_LEN 64

enum
{
    CL_SUBSCRIBER = 1,
    CL_PUBLISHER,
    CL_COMMANDER
};

int connect_client(char* host, char* port, char* topic);

#endif
