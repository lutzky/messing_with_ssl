CC=gcc
CFLAGS=-g -lssl

all: server server_ssl

server_ssl: server_ssl.c
server: server.c

clean:
	rm -f server server_ssl
