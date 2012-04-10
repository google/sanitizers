Experimental DynamoRIO-ASAN plugin --
allows to find heap-related bugs in the code which we do not
instrument with clang (e.g. system libraries).
Don't expect anything here to *really work*.

Building:
  1. First, download and build DynamoRIO:
     (svn co https://dynamorio.googlecode.com/svn/trunk dr && \
      cd dr && mkdir build && cd build && \
      cmake .. && make -j10)
  2. Now, build the tool
     (mkdir build && cd build && \
      cmake -DDynamoRIO_DIR=`pwd`/../dr/build/cmake .. && make -j10)

Running:
  1. See ../pin/README.txt on how to build the test app
  2. Run it with DR-ASan:
     ./dr/build/bin/drrun -client ./build/libdr_asan.so 0 "" -- ../pin/a.out
