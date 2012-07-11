Experimental DynamoRIO-MSAN plugin.

Building:
  1. First, download and build DynamoRIO:
     (svn co https://dynamorio.googlecode.com/svn/trunk dr && \
      cd dr && mkdir build && cd build && \
      cmake .. && make -j10)
  2. Now, build the tool
     (mkdir build && cd build && \
      cmake -DDynamoRIO_DIR=`pwd`/../dr/build/cmake .. && make -j10)

Running:
  LD_USE_LOAD_BIAS=1 ./dr/build/bin/drrun -client ./build/libmsandr.so 0 "" -- test
