.PHONY: default
default: all ;

all: memorynode memorynode_sim

CC=gcc
CFLAGS=-g -Wall
TARGET=memorynode memorynode_sim
SRC=ox_common.c memorynode.c

memorynode: ox_common.h $(SRC) Makefile
	$(CC) $(CFLAGS) -o $@ $(SRC)
	sudo setcap cap_net_raw+ep memorynode

memorynode_sim: ox_common.h $(SRC) Makefile
	$(CC) $(CFLAGS) -DSIM=1 -o $@ $(SRC)
	sudo setcap cap_net_raw+ep memorynode_sim

clean:
	rm -f *.o tags
	rm -f $(TARGET)
