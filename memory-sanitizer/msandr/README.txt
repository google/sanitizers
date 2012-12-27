Experimental DynamoRIO-MSAN plugin.

Building:
  1. First, download and build DynamoRIO:
     (svn co http://drmemory.googlecode.com/svn/trunk/ drmemory && \
      cd drmemory && mkdir build && cd build && \
      cmake -DDR_EXT_DRSYSCALL_STATIC=ON .. && make -j35)
  2. Now, build the tool
     (mkdir build && cd build && \
      cmake -DDynamoRIO_DIR=`pwd`/../drmemory/build/dynamorio/cmake \
            -DDrMemoryFramework_DIR=`pwd`/../drmemory/build/drmf .. && make)

Running:
  LD_USE_LOAD_BIAS=1 ./dr/build/bin/drrun -client ./build/libmsandr.so 0 "" -- test

Debugging:
  Add -DDEBUG=ON to all cmake invocations above.
  Add -debug -v to drrun invocation line (right before -client).

