.PHONY: default
default: all ;

all: memorynode

CC=gcc
CFLAGS=-g -Wall
TARGET=memorynode 
SRC=ox_common.c memorynode.c

memorynode: ox_common.h $(SRC) Makefile
	$(CC) $(CFLAGS) -DSIM=1 -o $@ $(SRC)
	sudo setcap cap_net_raw+ep memorynode

clean:
	rm -f *.o tags
	rm -f $(TARGET)
