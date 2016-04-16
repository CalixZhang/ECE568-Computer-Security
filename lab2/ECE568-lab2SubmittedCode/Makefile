CC := gcc
CFLAGS := -Wall
LIBS := -lssl -lcrypto
LDFLAGS := $(LIBS)
RM := rm -f

sources := client.c server.c sslfunctions.c
targets := client server 

.PHONY: clean default all

default: all
all: $(targets)

client: client.o sslfunctions.o
	$(CC) $(LDFLAGS) client.o sslfunctions.o -o client

server: server.o
	$(CC) $(LDFLAGS) server.o sslfunctions.o -o server


client.o: client.c
	$(CC) $(CFLAGS) -c -o client.o client.c

server.o: server.c
	$(CC) $(CFLAGS) -c -o server.o  server.c

sslfunctions.o: sslfunctions.c
	$(CC) $(CFLAGS) -c -o sslfunctions.o  sslfunctions.c

clean:
	$(RM) $(targets) $(sources:.c=.o) *~

