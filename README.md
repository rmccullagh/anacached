## Welcome to `anacached`

This is a proof of concept clone of memcached, supporting only GET and SET commands. 

Features:
- GET, SET
- Append only in memory hash table
- Configurable read buffer size
- 24 Byte binary protocol
- Multiplexed IO, (using epoll)
- REPL/CLI used to interfact with the protocol
- Simple to read code base

## Compile
```
git clone https://github.com/rmccullagh/anacached
cd anacached
make
maka anacli
```

## Run the server
```
anasever --listen-address 127.0.0.1 --port 8080 -v --enable-core-dumps 
```

## Run the CLI
```
anacli --server-address 127.0.0.1 --port 8080
```


## Commands
```
GET <key>
SET <key> <value>
```


## FAQ

Q: Memcached is already fast, why do you need to clone it? 
A: Memcached is an amazing piece of software. anacached was created in a long standing effort to read an understand the memcached daemon.

Q: Can you delete keys?
A: No, perhaps sometime in the future this will be implemented

Q: Why didn't you implement expirary times?
A: Expiring keys is not something that I feel is important to do at this time.  








