Experimental DynamoRIO-ASAN plugin --
allows to find heap-related bugs in the code which we do not
instrument with clang (e.g. system libraries).
Don't expect anything here to *really work*.

Building:
  1. First, download and build DynamoRIO:
     (svn co -r2108 https://dynamorio.googlecode.com/svn/trunk dr && \
      cd dr && mkdir build && cd build && \
      cmake -DDR_EXT_DRMGR_STATIC=ON  -DDR_EXT_DRSYMS_STATIC=ON \
            -DDR_EXT_DRUTIL_STATIC=ON -DDR_EXT_DRWRAP_STATIC=ON .. && \
      make -j10 && make install)
  2. Now, build the tool
     (mkdir build && cd build && \
      cmake -DDynamoRIO_DIR=`pwd`/../dr/exports/cmake .. && make -j10)

Running:
  1. See ../pin/README.txt on how to build the test app
  2. Run it with DR-ASan:
     ./dr/exports/bin64/drrun -c ./build/libdr_asan.so -- ../pin/a.out
