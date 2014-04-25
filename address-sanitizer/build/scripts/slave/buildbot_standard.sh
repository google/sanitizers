#!/bin/bash

set -x
set -e
set -u

HERE="$(dirname $0)"
. ${HERE}/buildbot_functions.sh

GCC_BUILD=/usr/local/gcc-4.8.2
export PATH="$GCC_BUILD/bin:$PATH"
export LD_LIBRARY_PATH=$GCC_BUILD/lib64

if [ "$BUILDBOT_CLOBBER" != "" ]; then
  echo @@@BUILD_STEP clobber@@@
  rm -rf llvm
  rm -rf llvm-build
fi

PLATFORM=`uname`
MAKE_JOBS=${MAX_MAKE_JOBS:-16}
BUILD_ASAN_ANDROID=${BUILD_ASAN_ANDROID:-0}
CHECK_TSAN=${CHECK_TSAN:-0}

echo @@@BUILD_STEP update@@@
buildbot_update

echo @@@BUILD_STEP build llvm@@@
if [ ! -d llvm-build ]; then
  mkdir llvm-build
fi
cd llvm-build
../llvm/configure --enable-optimized
make -j$MAKE_JOBS
cd ..
BUILD_ROOT=`pwd`
CLANG_BUILD=$BUILD_ROOT/llvm-build/Release+Asserts

echo @@@BUILD_STEP test llvm@@@
cd llvm-build
make check-all || echo @@@STEP_WARNINGS@@@

echo @@@BUILD_STEP sanity check for sanitizer tools@@@
CLANGXX_BINARY=$CLANG_BUILD/bin/clang++
echo -e "#include <stdio.h>\nint main(){ return 0; }" > temp.cc
for xsan in address undefined; do
  $CLANGXX_BINARY -fsanitize=$xsan -m64 temp.cc -o a.out
  ./a.out
  $CLANGXX_BINARY -fsanitize=$xsan -m32 temp.cc -o a.out
  ./a.out
done
if [ "$PLATFORM" == "Linux" ]; then
  for xsan in thread memory; do
    $CLANGXX_BINARY -fsanitize=$xsan -m64 temp.cc -o a.out
    ./a.out
  done
fi

if [ $BUILD_ASAN_ANDROID == 1 ] ; then
  echo @@@BUILD_STEP build asan/android runtime@@@
  make -j$MAKE_JOBS -C tools/clang/runtime/ \
      LLVM_ANDROID_TOOLCHAIN_DIR=$BUILD_ROOT/../../../android-ndk/standalone
fi

if [ $CHECK_TSAN == 1 ] ; then
  echo @@@BUILD_STEP prepare for testing tsan@@@

  TSAN_PATH=$BUILD_ROOT/llvm/projects/compiler-rt/lib/tsan/
  (cd $TSAN_PATH && make -f Makefile.old install_deps)

  export PATH=$CLANG_BUILD/bin:$GCC_BUILD/bin:$PATH
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
