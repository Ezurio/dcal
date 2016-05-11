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
CFLAGS += -Ilib.local/flatcc/include/
COMPILEONLY = -c

OBJECTS = $(patsubst src/%.c, $(OBJDIR)/%.o, $(wildcard src/*.c))

	CFLAGS += -ggdb -DDEBUG

APILIB = libdcal
LIB= $(APIDIR)/$(APILIB).so.1.0
all: $(LIB)

OPT_LIB = libsessopt.a

static: CFLAGS += -DSTATIC_MEM
static: remake

remake: clean all

.PHONY: all clean static
.DEFAULT: all

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) $(COMPILEONLY) $^ -o $@

$(LIB): $(OBJECTS) api/dcal_api.h
	$(CC) -shared -Wl,-soname,$(APILIB).so.1 \
	-o $(APILIB).so.1.0 $(OBJECTS) -lc $(LIBS)
	ln -fs $(APILIB).so.1.0 $(APILIB).so.1
	ln -fs $(APILIB).so.1.0 $(APILIB).so
	mv $(APILIB).so* $(APIDIR)

$(LIB).a:$(_OBJS)
	$(AR) rcs $(LIB).a $(_OBJS)

clean:
	rm -f $(SRCDIR)/*.o  $(APIDIR)/$(APILIB).*
	rm -rf $(OBJDIR)

$(APIDIR)/$(OPT_LIB): examples/common.c
	echo "build session option library"

#
# Library builds
#
lib:
	mkdir -p lib.local

lib.local/flatcc/lib/libflatcc.a : lib.local/flatcc
	cd lib.local/flatcc && git checkout v0.3.3
	cd lib.local/flatcc && ./scripts/build.sh

lib.local/flatcc : lib
	cd lib.local && git clone git@github.com:dvidelabs/flatcc.git

.PHONY: flatcc
flatcc: lib.local/flatcc/lib/libflatcc.a

####
#### test apps creation/clean
####
SUBDIRS := $(wildcard unit-tests/*/.)  # e.g. "foo/. bar/."
SUBDIRS += $(wildcard examples/*/.)  # e.g. "foo/. bar/."
TESTTARGETS := test_apps test_clean  # whatever else, but must not contain '/'

# foo/.all bar/.all foo/.clean bar/.clean
SUBDIRS_TARGETS := \
	$(foreach t,$(TESTTARGETS),$(addsuffix $t,$(SUBDIRS)))

.PHONY : $(TESTTARGETS) $(SUBDIRS_TARGETS)

# static pattern rule, expands into:
# all clean : % : foo/.% bar/.%
$(TESTTARGETS) : % : $(addsuffix %,$(SUBDIRS))
	@echo
	@echo 'Done with "$*" make target'

# here, for foo/.all:
#   $(@D) is foo
#   $(@F) is .all, with leading period
#   $(@F:.%=%) is just all
$(SUBDIRS_TARGETS) :
	$(MAKE) -C $(@D) $(@F:.%=%)
	@echo
