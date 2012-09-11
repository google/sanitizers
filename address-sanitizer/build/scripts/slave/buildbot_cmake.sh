#!/bin/bash

set -x
set -e
set -u

PLATFORM=`uname`

if [ "$BUILDBOT_CLOBBER" != "" ]; then
  echo @@@BUILD_STEP clobber@@@
  rm -rf llvm
  rm -rf llvm_build64
  rm -rf llvm_build32
fi

echo @@@BUILD_STEP update@@@
REV_ARG=
if [ "$BUILDBOT_REVISION" != "" ]; then
  REV_ARG="-r$BUILDBOT_REVISION"
fi

MAKE_JOBS=${MAX_MAKE_JOBS:-16}

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

ROOT=`pwd`
LLVM_CHECKOUT=$ROOT/llvm
BUILD_TYPE=Release
echo @@@BUILD_STEP build 64-bit llvm@@@
if [ ! -d llvm_build64 ]; then
  mkdir llvm_build64
  (cd llvm_build64 && cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE $LLVM_CHECKOUT)
fi
(cd llvm_build64 && make -j$MAKE_JOBS)

echo @@@BUILD_STEP build 32-bit llvm@@@
if [ ! -d llvm_build32 ]; then
  mkdir llvm_build32
  (cd llvm_build32 && cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
                            -DLLVM_BUILD_32_BITS=ON $LLVM_CHECKOUT)
fi
(cd llvm_build32 && make -j$MAKE_JOBS)

echo @@@BUILD_STEP lint@@@
CHECK_LINT=${LLVM_CHECKOUT}/projects/compiler-rt/lib/sanitizer_common/scripts/check_lint.sh
(LLVM_CHECKOUT=${LLVM_CHECKOUT} ${CHECK_LINT}) || echo @@@STEP_WARNINGS@@@

ASAN_PATH=projects/compiler-rt/lib/asan
ASAN_TESTS_PATH=$ASAN_PATH/tests
ASAN_TEST_BINARY=$ASAN_TESTS_PATH/$BUILD_TYPE/AsanTest

echo @@@BUILD_STEP run 64-bit asan tests@@@
(cd llvm_build64 && make -j$MAKE_JOBS check-asan)
# Run unit test binary in a single shard.
./llvm_build64/$ASAN_TEST_BINARY

echo @@@BUILD_STEP run 32-bit asan tests@@@
(cd llvm_build32 && make -j$MAKE_JOBS check-asan)
# Run unit test binary in a single shard.
./llvm_build32/$ASAN_TEST_BINARY

if [ "$PLATFORM" == "Darwin" ]; then
echo @@@BUILD_STEP build asan dynamic runtime@@@
# Building a fat binary for both 32 and 64 bits.
(cd llvm_build64/$ASAN_PATH && make -j$MAKE_JOBS clang_rt.asan_osx_dynamic)
fi

SANITIZER_COMMON_PATH=projects/compiler-rt/lib/sanitizer_common
SANITIZER_COMMON_TESTS=$SANITIZER_COMMON_PATH/tests
SANITIZER_COMMON_TEST_BINARY=${SANITIZER_COMMON_TESTS}/${BUILD_TYPE}/SanitizerUnitTest

echo @@@BUILD_STEP run 64-bit sanitizer tests@@@
(cd llvm_build64 && make -j$MAKE_JOBS check-sanitizer)
# Run unit test binary in a single shard.
./llvm_build64/${SANITIZER_COMMON_TEST_BINARY}

echo @@@BUILD_STEP run 32-bit sanitizer tests@@@
(cd llvm_build32 && make -j$MAKE_JOBS check-sanitizer)
# Run unit test binary in a single shard.
./llvm_build32/${SANITIZER_COMMON_TEST_BINARY}

ANDROID_TOOLCHAIN=$BUILD_ROOT/../../../android-ndk/standalone
if [ $BUILD_ANDROID == 1 ] ; then
    echo @@@BUILD_STEP build Android runtime and tests@@@

    if [ ! -d llvm_build64/android ]; then
        mkdir llvm_build64/android
        (cd llvm_build64/android && \
            cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
            -DLLVM_ANDROID_TOOLCHAIN_DIR=$ANDROID_TOOLCHAIN \
            -DCMAKE_TOOLCHAIN_FILE=$LLVM_CHECKOUT/cmake/platforms/Android.cmake \
            $LLVM_CHECKOUT)
    fi
    (cd llvm_build64/android && make -j$MAKE_JOBS AsanUnitTests)
fi
