#!/bin/bash

set -x
set -e
set -u


if [ "$BUILDBOT_CLOBBER" != "" ]; then
  echo @@@BUILD_STEP clobber@@@
  rm -rf llvm
fi

echo @@@BUILD_STEP update@@@
REV_ARG=
if [ "$BUILDBOT_REVISION" != "" ]; then
  REV_ARG="-r$BUILDBOT_REVISION"
fi

MAKE_JOBS=${MAX_MAKE_JOBS:-16}
CHECK_TSAN=${CHECK_TSAN:-0}

if [ -d llvm ]; then
  svn up llvm $REV_ARG
  if [ "$REV_ARG" == "" ]; then
    REV_ARG="-r"$(svn info llvm | grep '^Revision:' | awk '{print $2}')
  fi
  svn up llvm/tools/clang $REV_ARG
  svn up llvm/projects/compiler-rt $REV_ARG
else
  svn co http://llvm.org/svn/llvm-project/llvm/trunk llvm $REV_ARG
  if [ "$REV_ARG" == "" ]; then
    REV_ARG="-r"$(svn info llvm | grep '^Revision:' | awk '{print $2}')
  fi
  svn co http://llvm.org/svn/llvm-project/cfe/trunk llvm/tools/clang $REV_ARG
  svn co http://llvm.org/svn/llvm-project/compiler-rt/trunk llvm/projects/compiler-rt $REV_ARG
fi

echo @@@BUILD_STEP install deps@@@
ASAN_PATH=`pwd`/llvm/projects/compiler-rt/lib/asan/
TSAN_PATH=`pwd`/llvm/projects/compiler-rt/lib/tsan/
(cd $ASAN_PATH && make -f Makefile.old get_third_party)
(cd $TSAN_PATH && make -f Makefile.old install_deps)

echo @@@BUILD_STEP lint@@@
(cd $ASAN_PATH && make -f Makefile.old lint)
(cd $TSAN_PATH && make -f Makefile.old lint)

echo @@@BUILD_STEP build llvm@@@
rm -rf llvm-build
mkdir llvm-build
cd llvm-build
../llvm/configure --enable-optimized
make -j$MAKE_JOBS
cd ..
BUILD_ROOT=`pwd`
CLANG_BUILD=$BUILD_ROOT/llvm-build/Release+Asserts
GCC_BUILD=$BUILD_ROOT/../../../gcc

echo @@@BUILD_STEP test llvm@@@
cd llvm-build
make check-all || echo @@@STEP_WARNINGS@@@

echo @@@BUILD_STEP build asan@@@
cd $ASAN_PATH
make -f Makefile.old CLANG_BUILD=$CLANG_BUILD -j$MAKE_JOBS

echo @@@BUILD_STEP asan test32@@@
make -f Makefile.old CLANG_BUILD=$CLANG_BUILD t32  || echo @@@STEP_FAILURE@@@

echo @@@BUILD_STEP asan test64@@@
make -f Makefile.old CLANG_BUILD=$CLANG_BUILD t64  || echo @@@STEP_FAILURE@@@

echo @@@BUILD_STEP asan output_tests@@@
make -f Makefile.old CLANG_BUILD=$CLANG_BUILD output_tests  || echo @@@STEP_FAILURE@@@

if [ $CHECK_TSAN == 1 ] ; then
  echo @@@BUILD_STEP prepare for testing tsan@@@

  export PATH=$CLANG_BUILD/bin:$GCC_BUILD/bin:$PATH
  export LD_LIBRARY_PATH=$GCC_BUILD/lib64
  export MAKEFLAGS=-j$MAKE_JOBS
  gcc -v 2>tmp && grep "version" tmp
  clang -v 2>tmp && grep "version" tmp

  cd $BUILD_ROOT
  if [ -d tsanv2 ]; then
    (cd tsanv2 && svn up --ignore-externals)
  else
    svn co http://data-race-test.googlecode.com/svn/trunk/ tsanv2
  fi
  export RACECHECK_UNITTEST_PATH=$BUILD_ROOT/tsanv2/unittest

  cp $BUILD_ROOT/../../../scripts/slave/test_tsan.sh $TSAN_PATH
  (cd $TSAN_PATH && ./test_tsan.sh)
fi
