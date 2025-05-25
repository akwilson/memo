#pragma once

typedef struct memo_server memo_server_s;

/**
 * Initialises and sets up the socket for a new Memo server.
 *
 * @param `port` port number to listen on.
 *
 * @returns A freshly minted Memo server, ready to roll or NULL on failure.
 */
memo_server_s *memo_start_server(char *port);

/**
 * Blocking function which processes publish and subscribe events for the Memo server.
 *
 * @param `server` an initialised Memo server.
 *
 * @returns 0 on successful exit, non-zero otherwise.
 */
int memo_process_server(memo_server_s *server);

/**
 * Frees up the resources used by a Memo server.
 *
 * @param `server` the Memo server to be freed.
 */
void memo_free_server(memo_server_s *server);

// Subscriber functions
void* memo_connect_subscriber(char* host, char* port, char* topic);
void* memo_connect_subs(char* host, char* port, char* topics[], int num_topics);
int   memo_subs_add_topic(void* subscription, char* topics);
int   memo_subs_add_topics(void* subscription, char* topics[], int num_topics);
int   memo_subscribe(void* subscription, char** message, int* message_len);
void  memo_free_subscriber(void* subscription);

// Publisher functions
void* memo_connect_publisher(char* host, char* port);
int   memo_publish(void* publisher, char* topic, char* message, int message_len);
void  memo_free_publisher(void* publisher);

