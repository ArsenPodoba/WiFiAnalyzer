CC=gcc
LDFLAGS=$(shell pkg-config --libs libnl-genl-3.0) -lmnl
DEBUG_FLAGS=-DDEBUG=1 -std=c99 -Wall -Wextra -Wpedantic -g 
FLAGS= -Wall -Wpedantic -Wno-unused-parameter -I/usr/include/libnl3

ifeq (${DEBUG},1)
	FLAGS+=${DEBUG_FLAGS}
endif
FLAGS += $(shell pkg-config --cflags libnl-genl-3.0)

scanner: scanner.o
	${CC} -o $@ scanner.o ${LDFLAGS} ${FLAGS}

scanner.o: scanner.c
	${CC} -o $@ -c $< ${FLAGS}

clean:
	rm -rf *.o
