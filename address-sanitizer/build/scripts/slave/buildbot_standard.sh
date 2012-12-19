#!/bin/bash

set -x
set -e
set -u


if [ "$BUILDBOT_CLOBBER" != "" ]; then
  echo @@@BUILD_STEP clobber@@@
  rm -rf llvm
  rm -rf llvm-build
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

echo @@@BUILD_STEP build llvm@@@
if [ ! -d llvm-build ]; then
  mkdir llvm-build
  cd llvm-build
  ../llvm/configure --enable-optimized
else
  cd llvm-build
fi
make -j$MAKE_JOBS
cd ..
BUILD_ROOT=`pwd`
CLANG_BUILD=$BUILD_ROOT/llvm-build/Release+Asserts
GCC_BUILD=$BUILD_ROOT/../../../gcc

echo @@@BUILD_STEP test llvm@@@
cd llvm-build
make check-all || echo @@@STEP_WARNINGS@@@

if [ $CHECK_TSAN == 1 ] ; then
  echo @@@BUILD_STEP prepare for testing tsan@@@

  TSAN_PATH=$BUILD_ROOT/llvm/projects/compiler-rt/lib/tsan/
  (cd $TSAN_PATH && make -f Makefile.old install_deps)

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
