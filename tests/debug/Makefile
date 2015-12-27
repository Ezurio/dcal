LIBS = -lrmt_api

SOURCES=dbg_test.c

OBJS=$(SOURCES:.c=.o)

CFLAGS=-I../../api/

_EXE=dbg_test

all: $(_EXE)

$(_EXE): $(OBJS)
	$(CC) -o $@ $(OBJS) -L../../api $(LIBS)

%.o:%.c %.h
	$(CC) $(CFLAGS) -g -c -o $@ $<

clean:
	rm -f $(_EXE) *.o
