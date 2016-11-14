#ifndef MEMO_H
#define MEMO_H

// Hub functions
void* memo_start_server(char* port);
int   memo_process_server(void* server);
void  memo_free_server(void* server);

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

#endif
