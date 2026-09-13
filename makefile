
CFLAGS= -std=c17 -Wall -Wextra -Wpedantic


minigdb: src/main.c
	gcc $(CFLAGS) src/main.c -o minigdb

clean:
	rm -f minigdb