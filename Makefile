C = gcc
CFLAGS = -w -Wall -std=gnu99 -D_REENTRANT -D_XOPEN_SOURCE=500 -D_POSIX_C_SOURCE=200112L

LDFLAGS = -pthread 

#source code
SRC=$(wildcard *.c)
#headers (no need to be included)
HDR=$(wildcard *.h)
#will be the prerequisite
OBJ=$(SRC:.c=.o) $(UTIL:.c=.o)

node: $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LIBS)
	@echo "make Complete."

clean:
	rm node $(OBJ)
	@echo "$(OBJ) removed!"
