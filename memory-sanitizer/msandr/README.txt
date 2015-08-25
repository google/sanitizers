Experimental DynamoRIO-MSAN plugin.

Building:
  1. First, download and build DynamoRIO:
     (svn co https://dynamorio.googlecode.com/svn/trunk dr && \
      cd dr && mkdir build && cd build && \
      cmake -DDR_EXT_DRMGR_STATIC=ON -DDR_EXT_DRSYMS_STATIC=ON \
            -DDR_EXT_DRUTIL_STATIC=ON -DDR_EXT_DRWRAP_STATIC=ON .. && \
      make -j10 && make install)

  2. Download and build DrMemory (for DrSyscall extension:)
     (svn co http://drmemory.googlecode.com/svn/trunk/ drmemory && \
      cd drmemory && mkdir build && cd build && \
      cmake -DDynamoRIO_DIR=`pwd`/../../dr/exports/cmake \
            -DDR_EXT_DRSYSCALL_STATIC=ON .. && \
      make -j10 && make install)

  3. Now, build the tool
     (mkdir build && cd build && \
      cmake -DDynamoRIO_DIR=`pwd`/../dr/exports/cmake \
            -DDrMemoryFramework_DIR=`pwd`/../drmemory/exports64/drmf .. && \
      make)

Running:
  LD_USE_LOAD_BIAS=1 ./dr/exports/bin64/drrun -c ./build/libmsandr.so -- test

Debugging:
  Add -DCMAKE_BUILD_TYPE=Debug to the first and/or second cmake invocation(s).
  Add -DDEBUG=ON to the last cmake invocation.
  Add -debug -v to drrun invocation line (right before -c).
  Add -checklevel 1 to drrun (as the first argument) to make debug DR faster.

