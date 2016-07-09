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
