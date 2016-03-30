.PHONY:clean
CC=gcc
CFLAGS=-Wall -g
BIN=MiniFtp
OBJS=main.o sysutil.o session.o ftpproto.o privparent.o
$(BIN):$(OBJS)
	$(CC) $(CFLAGS) $^ -o $@
%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@
clean:
	rm -f *.o $(BIN)

