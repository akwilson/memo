#pragma once

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
#include <liburing.h>

#include "memo.h"

#define TOPIC_LEN 64
#define MSG_HEADER_LEN (4 + 1 + TOPIC_LEN)

/**
 * Messages incoming or outgoing are of one of these types.
 */
typedef enum msg_type
{
    OP_PUBLISH   = 0x01,
    OP_SUBSCRIBE = 0x02,
    OP_ADMIN     = 0x04,
    OP_CLOSE     = 0x08
} msg_type_e;

/**
 * Maps a topic to a message handler callback.
 */
typedef struct topic_handler
{
    char                 topic[TOPIC_LEN];
    memo_callback        callback;
    struct topic_handler *next;
} topic_handler_s;

struct memo_client
{
    int             socket;
    topic_handler_s *handlers;
};

/**
 * An message buffer to/from a client process.
 */
typedef struct
{
    size_t  len;
    uint8_t buf[];
} data_buffer_s;

