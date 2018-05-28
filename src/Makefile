CC = cc
CFLAGS = -O2 -Iinclude -Wall -Wextra -g -ggdb -std=gnu99
LDLIBS = -lm
LDFLAGS=-rdynamic
OBJECTS=anaserver.o ana_string.o ana_logging.o ana_message.o ana_map.o
PROTO_OBJECTS=anaproto.o ana_string.o ana_logging.o ana_message.o ana_map.o
CLI_OBJECTS=anacli.o ana_string.o ana_logging.o ana_message.o ana_map.o
ASYNC_CLI_OBJECTS=ana-async-cli.o ana_string.o ana_logging.o ana_message.o ana_map.o
PREFIX=/usr/local

anaserver: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o ../bin/$@ \
	../bin/anaserver.o \
	../bin/ana_string.o \
	../bin/ana_logging.o \
	../bin/ana_message.o \
	../bin/ana_map.o \
	$(LDLIBS)
	make install

## For the protocol test executable
anaproto: $(PROTO_OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o ../bin/$@ \
	../bin/anaproto.o \
	../bin/ana_string.o \
	../bin/ana_logging.o \
	../bin/ana_message.o \
	../bin/ana_map.o \
	$(LDLIBS)
	make install_ana_proto

	## For the protocol test executable
ana-async-cli: $(ASYNC_CLI_OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o ../bin/$@ \
	../bin/ana-async-cli.o \
	../bin/ana_string.o \
	../bin/ana_logging.o \
	../bin/ana_message.o \
	../bin/ana_map.o \
	$(LDLIBS)
	make install_async_cli

ana-async-cli.o: ana-async-cli.c
	$(CC) $(CFLAGS) -c $< -o ../bin/$@

anaproto.o: anaproto.c
	$(CC) $(CFLAGS) -c $< -o ../bin/$@

## end

## For the protocol test executable
anacli: $(CLI_OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o ../bin/$@ \
	../bin/anacli.o \
	../bin/ana_string.o \
	../bin/ana_logging.o \
	../bin/ana_message.o \
	../bin/ana_map.o \
	$(LDLIBS)
	make install_ana_cli

anacli.o: anacli.c
	$(CC) $(CFLAGS) -c $< -o ../bin/$@

## end

ana_map.o: ana_map.c
	$(CC) $(CFLAGS) -c $< -o ../bin/$@

anaserver.o: anaserver.c
	$(CC) $(CFLAGS) -c $< -o ../bin/$@

ana_string.o: ana_string.c
	$(CC) $(CFLAGS) -c $< -o ../bin/$@

ana_logging.o: ana_logging.c
	$(CC) $(CFLAGS) -c $< -o ../bin/$@

ana_message.o: ana_message.c
	$(CC) $(CFLAGS) -c $< -o ../bin/$@

install_ana_proto:
	cp ../bin/anaproto /home/ryan/bin

install_ana_cli:
	cp ../bin/anacli /home/ryan/bin

install_async_cli:
	cp ../bin/ana-async-cli /home/ryan/bin

install:
	cp ../bin/anaserver /home/ryan/bin

clean:
	rm -f ../bin/*
