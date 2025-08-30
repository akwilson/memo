#pragma once

#include <stdint.h>

/**
 * Opaque pointer to a Memo server instance.
 */
typedef struct memo_server memo_server_s;

/**
 * Opaque pointer to a Memo client instance.
 */
typedef struct memo_client memo_client_s;

/**
 * A Memo message contains data received from the server. This struct
 * is a fat pointer to some byte array data received. `topic` and `body`
 * point to positions within the byte array. Memo messages should be
 * freed after use.
 */
typedef struct memo_msg
{
    size_t        msg_len;  // total length of the message
    uint8_t       type;     // memo message type
    const char    *topic;   // the topic
    const uint8_t *body;    // the actual message content
    size_t        body_len; // length of the message content

    // private: internal use only
    uint8_t       *_raw_data;
    uint32_t      *_header;
} memo_msg_s;

/**
 * A callback to a subscription message handler function.
 *
 * @param `client` the Memo client that received the message
 * @param `msg`    the memo message received
 */
typedef void (*memo_callback)(memo_client_s *client, memo_msg_s msg);

/**
 * A function to allocate a Memo message.
 *
 * @param `size` the amount of memory to allocate
 *
 * @returns a pointer to the allocated memory
 */
typedef void *(*memo_alloc_fn)(size_t size);

/**
 * Initialises and sets up the socket for a new Memo server.
 *
 * @param `port` port number to listen on.
 *
 * @returns A freshly minted Memo server, ready to roll or NULL on failure.
 */
memo_server_s *memo_server_init(const char *port);

/**
 * Blocking function which processes publish and subscribe events for the Memo server.
 *
 * @param `server` an initialised Memo server.
 *
 * @returns 0 on successful exit, non-zero otherwise.
 */
int memo_server_process(memo_server_s *server);

/**
 * Frees up the resources used by a Memo server.
 *
 * @param `server` the Memo server to be freed.
 */
void memo_server_free(memo_server_s *server);

/**
 * Establishes a connection to a Memo server and returns a client instance.
 *
 * @param `hostname` name of the server hosting the Memo server
 * @param `port`     port number the Memo server listens on
 *
 * @returns a Memo client instance on success, NULL otherwise
 */
memo_client_s *memo_client_init(const char *hostname, const char *port);

/**
 * Specifies an allocator function to use with the memo client. Messages
 * received from the server will be allocated by the function specified.
 *
 * @param `client` the client with the connection to a Memo server
 * @param `alloc`  the function to be called to allocate a new message
 */
void memo_client_set_allocator(memo_client_s *client, memo_alloc_fn alloc);

/**
 * Registers a subscription with the Memo server.
 *
 * @param `client`   the client with the connection to a Memo server
 * @param `topic`    the topic to register the subscription against
 * @param `callback` function to be called when a message is received
 *
 * @returns 0 if successful, non-zero otherwise
 */
int memo_client_sub(memo_client_s *client, const char *topic, memo_callback callback);

/**
 * Publishes a message to a Memo server.
 *
 * @param `client`  the client with the connection to a Memo server
 * @param `topic`   the topic the message should be sent against
 * @param `message` the message to send
 * @param `len`     the message length
 *
 * @returns 0 if successful, non-zero otherwise
 */
int memo_client_pub(memo_client_s *client, const char *topic, const uint8_t *message, size_t len);

/**
 * Starts the event loop, listening to messages from the server and dispatching callbacks.
 *
 * @param `client` the client with the connection to a Memo server
 */
void memo_client_listen(memo_client_s *client);

/**
 * Free a memo message.
 *
 * @params `msg` the Memo message to be freed
 */
void memo_msg_free(memo_msg_s msg);

/**
 * Disconnects the client from the Memo server and frees its allocated resources.
 */
void memo_client_free(memo_client_s *client);
