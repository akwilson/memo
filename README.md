# Memo

A publish / subscribe message bus.

## Build

Because Memo uses io_uring it is only supported on Linux.
```sh
$ sudo apt install liburing-dev
```

Build it
```sh
$ make
```

Run the Python tests
```sh
$ make test
```

## Run
Run the Memo server on port 5000
```sh
$ ./build/memod 5000
```

## Connect from the command line
In another terminal window setup up a subscriber to the `news` topic
```sh
$ ./build/memo sub localhost 5000 news
```

And in yet another window publish some news
```sh
$ ./build/memo pub localhost 5000 news "Breaking news!"
```

## Write your own program to connect
```C
#include <string.h>
#include <memo.h>

/* Message handler called when a message is received */
static int handle_news(memo_client_s *mc, memo_msg_s msg)
{
    /* Do something imaginary with the message */
    const char *summary = summarise_story(msg);
    
    /* Publish a message to the 'news_summary' topic */
    memo_client_publish(mc, "news_summary", summary, strlen(summary));
    
    /* Free the message when done */
    memo_msg_free(msg);
}

int main()
{
    /* Establish a connection to a memo server */
    memo_client_s *mc = memo_client_init("localhost", "5000");
    
    /* Subscribe to the 'news' topic, calls back on the handle_news
       function when a message is received. */
    memo_client_subscribe(mc, "news", handle_news);
    
    /* Listen for messages and dispatch callback when received */
    memo_client_listen(mc);
    
    /* Free the client connection */
    memo_client_free(mc);
}
```
