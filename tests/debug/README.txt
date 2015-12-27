This test exercises various debug functionality in the API.  Not meant to be an example for customer usage, but instead, a test of the debug system of the API library.

tested with invocations:  (used with debug version of library)

make && ./dbg_test
make && LRD_API_DEBUG=1 LRD_API_DEBUG_LEVEL=6 ./dbg_test
make && LRD_API_DEBUG=time LRD_API_DEBUG_LEVEL=6 ./dbg_test
