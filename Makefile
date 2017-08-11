CFLAGS+=	-Wall -Weverything -Wextra -Wno-sign-conversion -Wno-bad-function-cast -pedantic -O0 -ggdb -lelf

default: all

all: tmips

tmips: tmips.c mips.c
	$(CC) $(CFLAGS) -o tmips tmips.c

clean:
	rm -f tmips

