CFLAGS+=	-Wall -Wextra -Wno-sign-conversion -Wno-bad-function-cast -pedantic -O3 -ggdb -lelf -L/usr/lib
CC=		gcc6

default: all

all: tmips

tmips: Makefile tmips.c mips.c
	$(CC) $(CFLAGS) -o tmips tmips.c

clean:
	rm -f tmips

