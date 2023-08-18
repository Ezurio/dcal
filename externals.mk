#
# External libraries
##############################################################################

#
# INCLUDE DIRECTORIES AND OPERATING SYSTEM LIBRARY
#
CFLAGS += -Wall -Werror --std=c99

BASE_DIR := $(CURDIR)

LIBSSH_VERSION := 0.10.5
FLATCC_VERSION := 0.6.1

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
# libssh has dependencies on libgcrypt20-dev libssl-dev
# These can be installed via apt on a Ubuntu machine.
lib.local/libssh : lib.local
	cd lib.local && wget -nc https://git.libssh.org/projects/libssh.git/snapshot/libssh-$(LIBSSH_VERSION).tar.gz
	cd lib.local/ && tar -xzf libssh-$(LIBSSH_VERSION).tar.gz
	mkdir -p lib.local/libssh-$(LIBSSH_VERSION)/build
	cd lib.local/libssh-$(LIBSSH_VERSION)/build && cmake -DCMAKE_INSTALL_PREFIX=$(BASE_DIR)/api ..
	cd lib.local/libssh-$(LIBSSH_VERSION)/build && make && make install

.PHONY: libssh
libssh: lib.local/libssh

clean_libssh:
	-rm -rf api/lib/
	-rm -rf api/include/libssh
	-rm -rf lib.local/libssh*

#
# flatcc
#
lib.local/flatcc : lib.local
	cd lib.local/ && wget -nc https://github.com/dvidelabs/flatcc/archive/refs/tags/v$(FLATCC_VERSION).tar.gz -O flatcc-$(FLATCC_VERSION).tar.gz
	cd lib.local/ && tar -xzf flatcc-$(FLATCC_VERSION).tar.gz && mv flatcc-$(FLATCC_VERSION) flatcc
	cd lib.local/flatcc && patch -p1 < ../../patches/flatcc001_add_fPIC.patch
	cp lib.local/flatcc/scripts/build.cfg.make lib.local/flatcc/scripts/build.cfg

lib.local/flatcc/lib/libflatcc.a : lib.local/flatcc
	cd lib.local/flatcc && ./scripts/build.sh

LIBFLATCC_INSTALL = api/libflatcc.a
$(LIBFLATCC_INSTALL) : lib.local/flatcc/lib/libflatcc.a
	mkdir -p api/lib && cp lib.local/flatcc/lib/*.a api/lib/.

.PHONY: flatcc
flatcc: lib.local/flatcc/lib/libflatcc.a $(LIBFLATCC_INSTALL)

.PHONY: clean_flatcc
clean_flatcc:
	-rm -rf lib.local/flatcc*
	-rm -f api/lib/libflatcc*

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
