TARGET = libsessopt.a
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld
AR := $(CROSS_COMPILE)ar
RANLIB += $(CROSS_COMPILE)ranlib
IDIR=../../api
APPDIR=../../apps/examples
LIBDIR=../../api
OBJDIR=obj

LIBS = -ldcal
LFLAGS = -L$(LIBDIR) $(LIBS)
CFLAGS = -g -Wall -I$(IDIR)

.PHONY: default all clean

default: $(LIBDIR)/$(TARGET)
all: default
test_apps: default
test_clean: clean

OBJECTS = $(patsubst %.c, $(OBJDIR)/%.o, $(wildcard *.c))
HEADERS = $(wildcard $(IDIR)/*.h)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(APPDIR):
	mkdir -p $(APPDIR)

$(OBJDIR)/%.o: %.c $(HEADERS) | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(APPDIR)/$(TARGET) $(OBJECTS)

$(LIBDIR)/$(TARGET): $(OBJECTS)
	$(AR) rv $@ $?
	$(RANLIB) $@

clean:
	-rm -rf $(OBJDIR)
	-rm -f $(LIBDIR)/$(TARGET)
