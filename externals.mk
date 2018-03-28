#
# External libraries
##############################################################################

#
# INCLUDE DIRECTORIES AND OPERATING SYSTEM LIBRARY
#
CFLAGS += -Wall -Werror --std=c99

BASE_DIR := $(CURDIR)

#
# COMPILER/ASSEMBLER INVOCATIONS
#
# Define RELEASE=1 on the command line to get
# We redefine CC to ensure gcc is used as 'cc' is the make default
ifdef RELEASE
  CFLAGS +=  -O3 $(INCLUDES)
  CXXFLAGS +=  -O3 $(INCLUDES)
else
  define DEBUGTXT
    @printf "\n#\n# Define RELEASE=1 on the command line to compile release version.\n"
    @printf "# Assuming debug compile. \n#\n"
  endef
  CFLAGS += -ggdb -fno-inline -DDEBUG_BUILD $(INCLUDES)
  CXXFLAGS += -ggdb -fno-inline -DDEBUG_BUILD $(INCLUDES)
endif

CC ?= gcc
CXX ?= g++


#
# TARGETS
#

.PHONY: all
all : libssh flatcc


lib.local:
	mkdir -p lib.local

#
# libssh
#
lib.local/libssh: lib.local
	cd lib.local && git clone git://git.libssh.org/projects/libssh.git

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
LIBSSH_TARGET := lib.local/libssh/build/src/libssh.so.4.4.2
LIBSSH_INSTALL := api/lib/libssh.so.4.4.2
endif
ifeq ($(UNAME_S),Darwin)
LIBSSH_TARGET := lib.local/libssh/build/src/libssh.4.4.2.dylib
LIBSSH_INSTALL := api/lib/libssh.4.4.2.dylib
endif


$(LIBSSH_TARGET): lib.local lib.local/libssh
	cd lib.local/libssh && git checkout libssh-0.7.5
	mkdir -p lib.local/libssh/build
	cd lib.local/libssh/build && cmake -DCMAKE_INSTALL_PREFIX=$(BASE_DIR)/api ..
	cd lib.local/libssh/build && make

$(LIBSSH_INSTALL): $(LIBSSH_TARGET)
	cd lib.local/libssh/build && make install

clean_libssh:
	-rm -rf api/lib/
	-rm -rf api/include/libssh

.PHONY: libssh
libssh: $(LIBSSH_TARGET) $(LIBSSH_INSTALL)

#
# flatcc
#
lib.local/flatcc : lib.local
	cd lib.local && git clone git@github.com:dvidelabs/flatcc.git
	cd lib.local/flatcc && git checkout v0.4.3
	cd lib.local/flatcc && patch -p1 < ../../patches/flatcc001_add_fPIC.patch
	cp lib.local/flatcc/scripts/build.cfg.make lib.local/flatcc/scripts/build.cfg

lib.local/flatcc/lib/libflatcc.a : lib.local/flatcc
	cd lib.local/flatcc && ./scripts/build.sh

LIBFLATCC_INSTALL = api/libflatcc.a
$(LIBFLATCC_INSTALL) : lib.local/flatcc/lib/libflatcc.a
	cp lib.local/flatcc/lib/*.a api/lib/.

.PHONY: flatcc
flatcc: lib.local/flatcc/lib/libflatcc.a $(LIBFLATCC_INSTALL)

.PHONY: clean_flatcc
clean_flatcc:
	-rm -f api/libflatcc*.a

export FLATCC := lib.local/flatcc/bin/flatcc

#
# Utility
#

.PHONY: clean
clean : clean_libssh clean_flatcc
	-rm -rf lib.local

.PHONY: cleanall
cleanall: clean

.PHONY: debug_msg
debug_msg:
	$(DEBUGTXT)

# help
.PHONY: help
help:
	@make --print-data-base --question | \
	awk '/^[^.%][-A-Za-z0-9_]*:/ \
	{ print substr($$1, 1, length($$1)-1) }' | \
	sort | \
	pr --omit-pagination --width=80 --columns=4

ifdef DUMPVARS
$(foreach v, $(.VARIABLES), $(info $(v) = $($(v))))
endif
