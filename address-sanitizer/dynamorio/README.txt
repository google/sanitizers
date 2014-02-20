Experimental DynamoRIO-ASAN plugin --
allows to find heap-related bugs in the code which we do not
instrument with clang (e.g. system libraries).
Don't expect anything here to *really work*.

Building:
  1. First, download DynamoRIO from
       http://build.chromium.org/p/client.dynamorio/builds/
     and extract it as 'dr'.

  2. Now, build the tool
     (mkdir build && cd build && \
      cmake -DDynamoRIO_DIR=`pwd`/../dr/cmake .. && make -j10) &&
     ln -s ../build/libdr_asan.so dr/ && ln -s ../run.sh dr

Running:
  1. See ../pin/README.txt on how to build the test app
  2. Run it with DR-ASan:
     ./dr/bin64/drrun -disable_traces -c ./dr/libdr_asan.so -- ../pin/a.out

Package:
  (cd dr && tar zcvh *) >package.tgz && cp package.tgz ~/drasan_package.tgz
