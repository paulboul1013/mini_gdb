CC := gcc
CFLAGS := -std=c17 -Wall -Wextra -Wpedantic -g

HELLO_SRC := examples/hello_ch6.c
MINIGDB_SRC := src/main.c

.PHONY: all clean

all: hello minigdb

hello: $(HELLO_SRC)
	$(CC) $(CFLAGS) $< -o $@

minigdb: $(MINIGDB_SRC)
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f hello minigdb