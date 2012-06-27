#!/bin/bash

set -x
set -e
set -u

echo @@@BUILD_STEP tsan build debug-clang@@@
make -f Makefile.old clean
make -f Makefile.old DEBUG=1 CC=clang CXX=clang++

echo @@@BUILD_STEP tsan test debug-clang@@@
./tsan_test

echo @@@BUILD_STEP tsan stats/output@@@
make -f Makefile.old clean
make -f Makefile.old DEBUG=1 CC=clang CXX=clang++ CFLAGS="-DTSAN_COLLECT_STATS=1 -DTSAN_DEBUG_OUTPUT=2"

echo @@@BUILD_STEP tsan build SHADOW_COUNT=4@@@
make -f Makefile.old clean
make -f Makefile.old DEBUG=1 CC=clang CXX=clang++ CFLAGS=-DTSAN_SHADOW_COUNT=4

echo @@@BUILD_STEP tsan test SHADOW_COUNT=4@@@
./tsan_test

echo @@@BUILD_STEP tsan build SHADOW_COUNT=2@@@
make -f Makefile.old clean
make -f Makefile.old DEBUG=1 CC=clang CXX=clang++ CFLAGS=-DTSAN_SHADOW_COUNT=2

echo @@@BUILD_STEP tsan test SHADOW_COUNT=2@@@
./tsan_test

echo @@@BUILD_STEP tsan build release-gcc@@@
make -f Makefile.old clean
make -f Makefile.old DEBUG=0 CC=gcc CXX=g++

echo @@@BUILD_STEP tsan test release-gcc@@@
./tsan_test

echo @@@BUILD_STEP tsan output_tests@@@
(cd output_tests && ./test_output.sh)

echo @@@BUILD_STEP tsan analyze@@@
./check_analyze.sh

echo @@@BUILD_STEP tsan racecheck_unittest@@@
TSAN_PATH=`pwd`
LIBTSAN_A=$TSAN_PATH/rtl/libtsan.a
SUPPRESS_WARNINGS="-Wno-format-security -Wno-null-dereference -Wno-unused-private-field"
EXTRA_COMPILER_FLAGS="-fthread-sanitizer -fPIC -g -O2 $SUPPRESS_WARNINGS"
(cd $RACECHECK_UNITTEST_PATH && \
make clean && \
OMIT_DYNAMIC_ANNOTATIONS_IMPL=1 LIBS=$LIBTSAN_A make l64 -j16 CC=clang CXX=clang++ LDOPT="-pie -ldl $LIBTSAN_A" OMIT_CPP0X=1 EXTRA_CFLAGS="$EXTRA_COMPILER_FLAGS" EXTRA_CXXFLAGS="$EXTRA_COMPILER_FLAGS" && \
bin/racecheck_unittest-linux-amd64-O0 --gtest_filter=-*Ignore*:*Suppress*:*EnableRaceDetectionTest*:*Rep*Test*:*NotPhb*:*Barrier*:*Death*:*PositiveTests_RaceInSignal*:StressTests.FlushStateTest:*Mmap84GTest)

#Ignore: ignores do not work yet
#Suppress: suppressions do not work yet
#EnableRaceDetectionTest: the annotation is not supported
#Rep*Test: uses inline assembly
#NotPhb: not-phb is not supported
#Barrier: pthread_barrier_t is not fully supported yet
#Death: there is some flakyness
#PositiveTests_RaceInSignal: signal() is not intercepted yet
#StressTests.FlushStateTest: uses suppressions
#Mmap84GTest: too slow, causes paging

