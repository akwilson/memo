# Memo

A publish / subscribe broker written in C.

## Build

Because Memo uses io_uring it is only supported on Linux.
```sh
$ sudo apt install luburing-dev
```

```sh
# Build it
$ make

# Run the Python tests
$ make test
```

## Run
Run the Memo server on port 5000
```sh
$ ./build/memod 5000
```
