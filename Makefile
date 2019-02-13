CFLAGS+=	-Wall -Wextra -Wno-sign-conversion -Wno-bad-function-cast -pedantic -O3 -march=native -mtune=native -ggdb -lelf -L/usr/lib
CC=		gcc8

default: all

all: tmips

opcodes.h: opcodes
	./opcodes.py opcodes opcodes.h

tmips: Makefile tmips.c mips.c opcodes.h
	$(CC) $(CFLAGS) -o tmips tmips.c

clean:
	rm -f tmips opcodes.h

