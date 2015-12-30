LIBS = -lrmt_api

SOURCES=session_test.c

OBJS=$(SOURCES:.c=.o)

CFLAGS=-I../../api/

_EXE=session_test

all: $(_EXE)

$(_EXE): $(OBJS)
	$(CC) -o $@ $(OBJS) -L../../api $(LIBS)

%.o:%.c %.h
	$(CC) $(CFLAGS) -g -c -o $@ $<

clean:
	rm -f $(_EXE) *.o
