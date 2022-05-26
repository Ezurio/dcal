TARGET = interface_test
CC ?= $(CROSS_COMPILE)gcc
LD ?= $(CROSS_COMPILE)ld
IDIR = ../../api
APPDIR = ../../apps/examples
LIBDIR = -L../../api -L../../api/lib
OBJDIR = obj

LIBS = -ldcal -lsessopt -lssh
LDFLAGS += $(LIBDIR) $(LIBS)
CFLAGS += -g -Wall -I$(IDIR)

.PHONY: default all clean

default: $(APPDIR)/$(TARGET)
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

$(APPDIR)/$(TARGET): $(OBJECTS) | $(APPDIR)
	$(CC) $(OBJECTS) -Wall $(LDFLAGS) -o $@

clean:
	-rm -rf $(OBJDIR)
	-rm -f $(APPDIR)/$(TARGET)
