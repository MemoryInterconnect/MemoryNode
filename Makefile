.PHONY: default
default: all ;

all: memorynode memorynode_sim memorynode_connectionless

CC=gcc
CFLAGS=-g -Wall
TARGET=memorynode memorynode_sim memorynode_connectionless
SRC=ox_common.c memorynode.c

memorynode: ox_common.h $(SRC) Makefile
	$(CC) $(CFLAGS) -o $@ $(SRC)
	sudo setcap cap_net_raw+ep memorynode

memorynode_sim: ox_common.h $(SRC) Makefile
	$(CC) $(CFLAGS) -DSIM=1 -o $@ $(SRC)
	sudo setcap cap_net_raw+ep memorynode_sim

memorynode_connectionless: ox_common.h ox_common_connectionless.c memorynode_connectionless.c Makefile
	$(CC) $(CFLAGS) -o $@ ox_common_connectionless.c memorynode_connectionless.c
	sudo setcap cap_net_raw+ep memorynode_connectionless

clean:
	rm -f *.o tags
	rm -f $(TARGET)
