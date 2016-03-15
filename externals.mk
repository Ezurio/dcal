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


lib:
	mkdir -p lib

#
# libssh
#
lib/libssh: lib
	cd lib && git clone git://git.libssh.org/projects/libssh.git

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
LIBSSH_TARGET := lib/libssh/build/src/libssh.so.4.4.0
LIBSSH_INSTALL := api/lib/libssh.so.4.4.0
endif
ifeq ($(UNAME_S),Darwin)
LIBSSH_TARGET := lib/libssh/build/src/libssh.4.4.0.dylib
LIBSSH_INSTALL := api/lib/libssh.4.4.0.dylib
endif


$(LIBSSH_TARGET): lib lib/libssh
	cd lib/libssh && git checkout 4d43fbfb50710055352c4fda812b6dc98143d336
	mkdir -p lib/libssh/build
	cd lib/libssh/build && cmake -DCMAKE_INSTALL_PREFIX=$(BASE_DIR)/api ..
	cd lib/libssh/build && make

$(LIBSSH_INSTALL): $(LIBSSH_TARGET)
	cd lib/libssh/build && make install

clean_libssh:
	-rm -rf api/lib/
	-rm -rf api/include/libssh

.PHONY: libssh
libssh: $(LIBSSH_TARGET) $(LIBSSH_INSTALL)

#
# flatcc
#
lib/flatcc : lib
	cd lib && git clone git@github.com:dvidelabs/flatcc.git
	cd lib/flatcc && git checkout v0.2.0
	cd lib/flatcc && patch -p0 < ../../patches/flatcc001_ninja-to-make.patch

lib/flatcc/lib/libflatcc.a : lib/flatcc
	cd lib/flatcc && ./scripts/build.sh

LIBFLATCC_INSTALL = api/libflatcc.a
$(LIBFLATCC_INSTALL) : lib/flatcc/lib/libflatcc.a
	cp lib/flatcc/lib/*.a api/.

.PHONY: flatcc
flatcc: lib/flatcc/lib/libflatcc.a $(LIBFLATCC_INSTALL)

.PHONY: clean_flatcc
clean_flatcc:
	-rm -f api/libflatcc*.a

export FLATCC := lib/flatcc/bin/flatcc

#
# Utility
#

.PHONY: clean
clean : clean_libssh clean_flatcc
	-rm -rf lib

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
