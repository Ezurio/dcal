# this make file uses the CROSS_COMPILE environment variable to indicate
# the correct compiler.

# Allow CROSS_COMPILE to specify compiler base
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld

OBJDIR := obj
SRCDIR := src
APIDIR := api

LIBS   +=

CFLAGS += -Wall -Werror -fPIC -I$(SRCDIR)/include -I$(SRCDIR) -I$(APIDIR)
COMPILEONLY = -c

SOURCES = $(SRCDIR)/placeholder.c
SOURCES += $(SRCDIR)/debug.c

# could use this to add all .c files if not wanting to list them above,
# but will include debug.c by default
# SOURCES := $(shell find $(SRCDIR) -type f -name *.c)

ifdef DEBUG
	CFLAGS += -ggdb -DDEBUG
endif

LIB = librmt_api

.PHONY: all clean
.DEFAULT: all

OBJECTS := $(patsubst $(SRCDIR)/%,$(OBJDIR)/%,$(SOURCES:.c=.o))

all: $(LIB)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) $(COMPILEONLY) $^ -o $@

$(LIB): $(OBJECTS)
	$(CC) -shared -Wl,-soname,$(LIB).so.1 \
	-o $(APIDIR)/$(LIB).so.1.0 $(OBJECTS) -lc $(LIBS)
	ln -fs $(LIB).so.1.0 $(LIB).so
	mv $(LIB).so $(APIDIR)

$(LIB).a:$(_OBJS)
	$(AR) rcs $(LIB).a $(_OBJS)

clean: clean_test
	rm -f $(SRCDIR)/*.o  $(APIDIR)/$(LIB).*
	rm -r $(OBJDIR)

test_apps:
	mkdir -p $(APIDIR)/test
	@echo build the test apps which will be under src/test.  Should put \
	objects under api/test

clean_test:
	rm -rf $(APIDIR)/test

