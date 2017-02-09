Device Control API Library (DCAL) (Released under the ISC License)

This repo contains the open-source remote API project for LAIRD WB remote setup.

To create, run MAKE.  This will create the library librmt_api.so.1.0.  A symlink names lib_rm_api.so will also be created.

The files lrd_remote_API.h and lib_rmt_api.so can then be used to create localized software that can access the WB remotely.

To make the debug version, issue the command:
make clean && make DEBUG=1
This will create a debug version of the library and output information from your app to stdout.  NOTE: may not compile/run correctly on your system depending on your compiler and libraries installed.

To make the test apps, issue:
make test_apps


To run, you will need to set your LD_LIBRARY_PATH. This requires a full path:

export LD_LIBRARY_PATH="~/projects/dcal/api:$LD_LIBRARY_PATH"

Then you can run the examples.

Quick Start
-----------

    clone git@github.com:LairdCP/dcal.git
    cd dcal
    make -f externals.mk
    make DEBUG=1
    make test_apps
    export LD_LIBRARY_PATH="$PWD/api:$LD_LIBRARY_PATH"
    cd apps/examples
    ./status_test


Python
------

We include a python binding, dcal_py. This is a very thin binding that is utilized and
intended mainly for the test framework. It is an optional component.

### Requirements ###

1. dcal_py requires that libssh and libflatccrt be included directly in libdcal.
This is already accomplished by a few build fixes.
2. The python binding utilizes boost::python to make it easy to create. I utilized boost version 1.57. Newer versions probably will work, later might not.
3. The version of python on my machine is 2.7. The Makefile is plumbed for
python2.7 on Ubuntu 14.04 LTS. If you use a different version,  you may need
to make minor adjustments to the makefile, or install python2.7 on your host.

### Building dcal_py ###

    make python

### Using dcal_py ###

Wherever you are, python will need to be able to find both `dcal_py.so` and
`lib_dcal.so`. You need to set `LD_LIBRARY_PATH` and `PYTHONPATH` to the api
directory:

    export LD_LIBRARY_PATH="$PWD/api:$LD_LIBRARY_PATH"
    export PYTHONPATH="$PWD/api"

Then you can use. For example, after the above, start python and use it:

    derosier@elmer:~/projects/wtf/tests$ python
    Python 2.7.6 (default, Jun 22 2015, 17:58:13)
    [GCC 4.8.2] on linux2
    Type "help", "copyright", "credits" or "license" for more information.
    >>> import dcal_py
    >>> d = dcal_py.dcal()
    >>> print d.session_create()
    0
    >>> print d.host('192.168.0.66')
    0
    >>> print d.port(2222)
    0
    >>> print d.user('libssh')
    0
    >>> print d.pw('libssh')
    0
    >>> print d.session_open()
    0
    >>> print d.session_close()
    0
    >>>

Note that a 0 return is `DCAL_SUCCESS`.
