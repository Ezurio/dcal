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

OBJECTS = $(patsubst src/%.c, $(OBJDIR)/%.o, $(wildcard src/*.c))

ifdef DEBUG
	CFLAGS += -ggdb -DDEBUG
endif

APILIB = librmt_api

LIB= $(APIDIR)/$(APILIB).so.1.0

.PHONY: all clean
.DEFAULT: all

all: $(LIB)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) $(COMPILEONLY) $^ -o $@

$(LIB): $(OBJECTS)
	$(CC) -shared -Wl,-soname,$(LIB).so.1 \
	-o $(LIB) $(OBJECTS) -lc $(LIBS)
	ln -fs $(APILIB).so.1.0 $(APILIB).so
	mv $(APILIB).so $(APIDIR)

$(LIB).a:$(_OBJS)
	$(AR) rcs $(LIB).a $(_OBJS)

clean: 
	rm -f $(SRCDIR)/*.o  $(APIDIR)/$(LIB).*
	rm -r $(OBJDIR)

####
#### test apps creation/clean
####
TESTSUBDIRS := $(wildcard tests/*/.)  # e.g. "foo/. bar/."
TESTTARGETS := test_apps test_clean  # whatever else, but must not contain '/'

# foo/.all bar/.all foo/.clean bar/.clean
SUBDIRS_TARGETS := \
	$(foreach t,$(TESTTARGETS),$(addsuffix $t,$(TESTSUBDIRS)))

.PHONY : $(TESTTARGETS) $(SUBDIRS_TARGETS)

# static pattern rule, expands into:
# all clean : % : foo/.% bar/.%
$(TESTTARGETS) : % : $(addsuffix %,$(TESTSUBDIRS))
	@echo 'Done with "$*" make target'

# here, for foo/.all:
#   $(@D) is foo
#   $(@F) is .all, with leading period
#   $(@F:.%=%) is just all
$(SUBDIRS_TARGETS) :
	$(MAKE) -C $(@D) $(@F:.%=%)
