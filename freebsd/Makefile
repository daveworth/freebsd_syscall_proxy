CC = gcc
CFLAGS = -g -Wall -pedantic

all: syscall_client.c syscall_server.s
	$(CC) $(CFLAGS) syscall_client.c -o syscall_client
	$(CC) $(CFLAGS) syscall_server.s -o syscall_server

clean:
	rm -f syscall_client syscall_server *~ *.core
