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
 * A fat pointer referencing some data held in a buffer.
 */
typedef struct
{
    size_t  len;
    uint8_t *ptr;
} data_slice_s;
