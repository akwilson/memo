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

In another terminal window setup up a subscriber to the `news` topic
```sh
$ ./build/memo sub localhost 5000 news
```

And in yet another window publish some news
```sh
$ ./build/memo pub localhost 5000 news "Breaking news!"
```
