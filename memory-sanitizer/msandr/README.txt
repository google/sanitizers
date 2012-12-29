Experimental DynamoRIO-MSAN plugin.

Building:
  1. First, download and build DynamoRIO:
     (svn co http://drmemory.googlecode.com/svn/trunk/ drmemory && \
      cd drmemory && mkdir build && cd build && \
      cmake -DDR_EXT_DRSYSCALL_STATIC=ON .. && make -j35 -k; make drsyscall drutil drmgr drpreload -j35)
     Yes, full build with static drsyscall fails. Yes, parallel build of the 4
     targets above fails, too - but for different reasons, and not after a full
     build has been attempted!
  2. Now, build the tool
     (mkdir build && cd build && \
      cmake -DDynamoRIO_DIR=`pwd`/../drmemory/build/dynamorio/cmake .. && make)

Running:
  LD_USE_LOAD_BIAS=1 ./dr/build/bin/drrun -client ./build/libmsandr.so 0 "" -- test

Debugging:
  Add -DCMAKE_BUILD_TYPE=Debug to the first cmake invocation.
  Add -DDEBUG=ON to the second cmake invocation.
  Add -debug -v to drrun invocation line (right before -client).

