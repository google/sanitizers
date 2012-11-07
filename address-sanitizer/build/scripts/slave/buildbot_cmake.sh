#!/bin/bash

set -x
set -e
set -u

ROOT=`pwd`
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
LLVM_CHECKOUT=$ROOT/llvm

CMAKE_COMMON_OPTIONS="-DLLVM_ENABLE_ASSERTIONS=ON"
if [ "$PLATFORM" == "Darwin" ]; then
  CMAKE_COMMON_OPTIONS="${CMAKE_COMMON_OPTIONS} -DPYTHON_EXECUTABLE=/usr/bin/python"
fi

if [ "$PLATFORM" == "Darwin" ]; then
  # Use bootstrap build on Darwin: first build clang, then use this new
  # clang to build and run ASan tests.
  echo @@@BUILD_STEP build fresh clang@@@
  if [ ! -d clang_build ]; then
    mkdir clang_build
  fi
  (cd clang_build && cmake -DCMAKE_BUILD_TYPE=Release \
      ${CMAKE_COMMON_OPTIONS} $LLVM_CHECKOUT)
  (cd clang_build && make clang -j$MAKE_JOBS) || echo @@@STEP_FAILURE@@@
  CLANG=${ROOT}/clang_build/bin/clang
  export CC=${CLANG}
  export CXX=${CLANG}++
fi

BUILD_TYPE=Release
echo @@@BUILD_STEP build 64-bit llvm@@@
if [ ! -d llvm_build64 ]; then
  mkdir llvm_build64
fi
(cd llvm_build64 && cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
    ${CMAKE_COMMON_OPTIONS} $LLVM_CHECKOUT)
(cd llvm_build64 && make -j$MAKE_JOBS) || echo @@@STEP_FAILURE@@@

echo @@@BUILD_STEP build 32-bit llvm@@@
if [ ! -d llvm_build32 ]; then
  mkdir llvm_build32
fi
(cd llvm_build32 && cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
    -DLLVM_BUILD_32_BITS=ON \
    ${CMAKE_COMMON_OPTIONS} \
    $LLVM_CHECKOUT)
(cd llvm_build32 && make -j$MAKE_JOBS) || echo @@@STEP_FAILURE@@@

echo @@@BUILD_STEP lint@@@
CHECK_LINT=${LLVM_CHECKOUT}/projects/compiler-rt/lib/sanitizer_common/scripts/check_lint.sh
(LLVM_CHECKOUT=${LLVM_CHECKOUT} ${CHECK_LINT}) || echo @@@STEP_WARNINGS@@@

ASAN_PATH=projects/compiler-rt/lib/asan
ASAN_TESTS_PATH=$ASAN_PATH/tests
ASAN_TEST_BINARY=$ASAN_TESTS_PATH/$BUILD_TYPE/AsanTest
TSAN_PATH=projects/compiler-rt/lib/tsan
TSAN_RTL_TEST_BINARY=$TSAN_PATH/tests/rtl/$BUILD_TYPE/TsanRtlTest
TSAN_UNIT_TEST_BINARY=$TSAN_PATH/tests/unit/$BUILD_TYPE/TsanUnitTest

echo @@@BUILD_STEP run 64-bit asan tests@@@
(cd llvm_build64 && make -j$MAKE_JOBS check-asan) || echo @@@STEP_FAILURE@@@
# Run unit test binary in a single shard.
./llvm_build64/$ASAN_TEST_BINARY

echo @@@BUILD_STEP run 32-bit asan tests@@@
(cd llvm_build32 && make -j$MAKE_JOBS check-asan) || echo @@@STEP_FAILURE@@@
# Run unit test binary in a single shard.
./llvm_build32/$ASAN_TEST_BINARY

if [ "$PLATFORM" == "Linux" ]; then
echo @@@BUILD_STEP run 64-bit tsan unit tests@@@
(cd llvm_build64 && make -j$MAKE_JOBS check-tsan) || echo @@@STEP_FAILURE@@@
# Run tsan unit test binaries.
./llvm_build64/$TSAN_RTL_TEST_BINARY
./llvm_build64/$TSAN_UNIT_TEST_BINARY
fi

if [ "$PLATFORM" == "Darwin" ]; then
echo @@@BUILD_STEP build asan dynamic runtime@@@
# Building a fat binary for both 32 and 64 bits.
(cd llvm_build64/$ASAN_PATH && make -j$MAKE_JOBS clang_rt.asan_osx_dynamic) || echo @@@STEP_FAILURE@@@
fi

SANITIZER_COMMON_PATH=projects/compiler-rt/lib/sanitizer_common
SANITIZER_COMMON_TESTS=$SANITIZER_COMMON_PATH/tests
SANITIZER_COMMON_TEST_BINARY=${SANITIZER_COMMON_TESTS}/${BUILD_TYPE}/SanitizerUnitTest

echo @@@BUILD_STEP run 64-bit sanitizer tests@@@
(cd llvm_build64 && make -j$MAKE_JOBS check-sanitizer) || echo @@@STEP_FAILURE@@@
# Run unit test binary in a single shard.
./llvm_build64/${SANITIZER_COMMON_TEST_BINARY}

echo @@@BUILD_STEP run 32-bit sanitizer tests@@@
(cd llvm_build32 && make -j$MAKE_JOBS check-sanitizer) || echo @@@STEP_FAILURE@@@
# Run unit test binary in a single shard.
./llvm_build32/${SANITIZER_COMMON_TEST_BINARY}

BUILD_ANDROID=${BUILD_ANDROID:-0}
if [ $BUILD_ANDROID == 1 ] ; then
    echo @@@BUILD_STEP build Android runtime and tests@@@
    ANDROID_TOOLCHAIN=$ROOT/../../../android-ndk/standalone

    # Always clobber android build tree.
    # It has a hidden dependency on clang (through CXX) which is not known to
    # the build system.
    rm -rf llvm_build64/android
    mkdir llvm_build64/android
    (cd llvm_build64/android && \
        cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
        -DLLVM_ANDROID_TOOLCHAIN_DIR=$ANDROID_TOOLCHAIN \
        -DCMAKE_TOOLCHAIN_FILE=$LLVM_CHECKOUT/cmake/platforms/Android.cmake \
        ${CMAKE_COMMON_OPTIONS} \
        $LLVM_CHECKOUT)
    (cd llvm_build64/android && make -j$MAKE_JOBS AsanUnitTests) || echo @@@STEP_FAILURE@@@
fi

RUN_ANDROID=${RUN_ANDROID:-0}
if [ $RUN_ANDROID == 1 ] ; then
    echo @@@BUILD_STEP run Android tests@@@
    ADB=$ROOT/../../../android-sdk-linux/platform-tools/adb
    DEVICE_ROOT=/data/local/asan_test

    echo "Rebooting the device"
    $ADB reboot
    $ADB wait-for-device
    sleep 5

    $ADB devices

    $ADB root

    sleep 5
    $ADB shell rm -rf $DEVICE_ROOT
    $ADB shell mkdir $DEVICE_ROOT

    ASAN_RT_LIB=libclang_rt.asan-arm-android.so
    ASAN_RT_LIB_PATH=`find llvm_build64/android/lib -name $ASAN_RT_LIB`
    echo "ASan runtime: $ASAN_RT_LIB_PATH"
    $ADB push $ASAN_RT_LIB_PATH $DEVICE_ROOT/
    $ADB push llvm_build64/android/projects/compiler-rt/lib/asan/tests/Release/AsanTest $DEVICE_ROOT/

    $ADB shell "LD_PRELOAD=$DEVICE_ROOT/$ASAN_RT_LIB \
        LD_LIBRARY_PATH=$DEVICE_ROOT \
        $DEVICE_ROOT/AsanTest \
        --gtest_filter=-AddressSanitizer.MemsetWildAddressTest; \
        echo \$? >$DEVICE_ROOT/error_code"
    $ADB pull $DEVICE_ROOT/error_code error_code && (exit `cat error_code`) || echo @@@STEP_FAILURE@@@
fi
