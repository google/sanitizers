#!/bin/bash

set -x
set -e
set -u

HERE="$(dirname $0)"
. ${HERE}/buildbot_functions.sh

ROOT=`pwd`
PLATFORM=`uname`
export PATH="/usr/local/bin:$PATH"

if [ "$BUILDBOT_CLOBBER" != "" ]; then
  echo @@@BUILD_STEP clobber@@@
  rm -rf llvm
  rm -rf llvm_build64
  rm -rf llvm_build_ninja
  rm -rf clang_build
fi

MAKE_JOBS=${MAX_MAKE_JOBS:-16}
LLVM_CHECKOUT=$ROOT/llvm
CMAKE_COMMON_OPTIONS="-DLLVM_ENABLE_ASSERTIONS=ON"
if [ "$PLATFORM" == "Darwin" ]; then
  CMAKE_COMMON_OPTIONS="${CMAKE_COMMON_OPTIONS} -DPYTHON_EXECUTABLE=/usr/bin/python"
fi


echo @@@BUILD_STEP update@@@
buildbot_update


echo @@@BUILD_STEP lint@@@
CHECK_LINT=${LLVM_CHECKOUT}/projects/compiler-rt/lib/sanitizer_common/scripts/check_lint.sh
(LLVM_CHECKOUT=${LLVM_CHECKOUT} ${CHECK_LINT}) || echo @@@STEP_WARNINGS@@@

# Use both gcc and just-built Clang as a host compiler for sanitizer tests.
# Assume that self-hosted build tree should compile with -Werror.
echo @@@BUILD_STEP build fresh clang@@@
if [ ! -d clang_build ]; then
  mkdir clang_build
fi
(cd clang_build && cmake -DCMAKE_BUILD_TYPE=Release \
    ${CMAKE_COMMON_OPTIONS} $LLVM_CHECKOUT)
(cd clang_build && make clang -j$MAKE_JOBS) || echo @@@STEP_FAILURE@@@

# Do a sanity check on Linux: build and test sanitizers using gcc as a host
# compiler.
if [ "$PLATFORM" == "Linux" ]; then
  echo @@@BUILD_STEP run sanitizer tests in gcc build@@@
  (cd clang_build && make -j$MAKE_JOBS check-sanitizer) || echo @@@STEP_FAILURE@@@
  (cd clang_build && make -j$MAKE_JOBS check-asan) || echo @@@STEP_FAILURE@@@
  (cd clang_build && make -j$MAKE_JOBS check-lsan) || echo @@@STEP_FAILURE@@@
  (cd clang_build && make -j$MAKE_JOBS check-msan) || echo @@@STEP_FAILURE@@@
  (cd clang_build && make -j$MAKE_JOBS check-tsan) || echo @@@STEP_FAILURE@@@
  (cd clang_build && make -j$MAKE_JOBS check-ubsan) || echo @@@STEP_WARNINGS@@@
fi

### From now on we use just-built Clang as a host compiler ###
CLANG_PATH=${ROOT}/clang_build/bin
# Build self-hosted tree with fresh Clang and -Werror.
CMAKE_CLANG_OPTIONS="${CMAKE_COMMON_OPTIONS} -DCMAKE_C_COMPILER=${CLANG_PATH}/clang -DCMAKE_CXX_COMPILER=${CLANG_PATH}/clang++ -DLLVM_ENABLE_WERROR=ON"
# TODO: Remove this warning suppression when LLVM r173643 is fixed/reverted.
CMAKE_CLANG_OPTIONS="${CMAKE_CLANG_OPTIONS} -DCMAKE_C_FLAGS=-Wno-nested-anon-types -DCMAKE_CXX_FLAGS=-Wno-nested-anon-types"
BUILD_TYPE=Release

echo @@@BUILD_STEP build 64-bit llvm using clang@@@
if [ ! -d llvm_build64 ]; then
  mkdir llvm_build64
fi
(cd llvm_build64 && cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
    ${CMAKE_CLANG_OPTIONS} $LLVM_CHECKOUT)
(cd llvm_build64 && make -j$MAKE_JOBS) || echo @@@STEP_FAILURE@@@

echo @@@BUILD_STEP run asan tests@@@
ASAN_PATH=projects/compiler-rt/lib/asan
ASAN_TESTS_PATH=$ASAN_PATH/tests
ASAN_TEST_BINARY_64=$ASAN_TESTS_PATH/Asan-x86_64-Test
ASAN_TEST_BINARY_32=$ASAN_TESTS_PATH/Asan-i386-Test
(cd llvm_build64 && make -j$MAKE_JOBS check-asan) || echo @@@STEP_FAILURE@@@
# Run unit test binaries in a single shard.
./llvm_build64/$ASAN_TEST_BINARY_64
./llvm_build64/$ASAN_TEST_BINARY_32

if [ "$PLATFORM" == "Darwin" ]; then
  echo @@@BUILD_STEP build asan dynamic runtime@@@
  # Building a fat binary for both 32 and 64 bits.
  (cd llvm_build64/$ASAN_PATH && make -j$MAKE_JOBS clang_rt.asan_osx_dynamic) || echo @@@STEP_FAILURE@@@
fi

if [ "$PLATFORM" == "Linux" ]; then
  echo @@@BUILD_STEP run msan unit tests@@@
  MSAN_PATH=projects/compiler-rt/lib/msan
  MSAN_UNIT_TEST_BINARY=$MSAN_PATH/tests/Msan-x86_64-Test
  (cd llvm_build64 && make -j$MAKE_JOBS check-msan) || echo @@@STEP_FAILURE@@@
  # Run msan unit test binaries.
  ./llvm_build64/$MSAN_UNIT_TEST_BINARY
fi

if [ "$PLATFORM" == "Linux" ]; then
  echo @@@BUILD_STEP run 64-bit tsan unit tests@@@
  TSAN_PATH=projects/compiler-rt/lib/tsan
  TSAN_RTL_TEST_BINARY=$TSAN_PATH/tests/rtl/TsanRtlTest
  TSAN_UNIT_TEST_BINARY=$TSAN_PATH/tests/unit/TsanUnitTest
  (cd llvm_build64 && make -j$MAKE_JOBS check-tsan) || echo @@@STEP_FAILURE@@@
  # Run tsan unit test binaries.
  ./llvm_build64/$TSAN_RTL_TEST_BINARY
  ./llvm_build64/$TSAN_UNIT_TEST_BINARY
fi

if [ "$PLATFORM" == "Linux" ]; then
  echo @@@BUILD_STEP run 64-bit lsan unit tests@@@
  LSAN_PATH=projects/compiler-rt/lib/lsan
  LSAN_UNIT_TEST_BINARY=$LSAN_PATH/tests/Lsan-x86_64-Test
  (cd llvm_build64 && make -j$MAKE_JOBS check-lsan) || echo @@@STEP_FAILURE@@@
  # Run msan unit test binaries.
  ./llvm_build64/$MSAN_UNIT_TEST_BINARY
fi

echo @@@BUILD_STEP run sanitizer_common tests@@@
SANITIZER_COMMON_PATH=projects/compiler-rt/lib/sanitizer_common
SANITIZER_COMMON_TESTS=$SANITIZER_COMMON_PATH/tests
SANITIZER_COMMON_TEST_BINARY_64=${SANITIZER_COMMON_TESTS}/Sanitizer-x86_64-Test
SANITIZER_COMMON_TEST_BINARY_32=${SANITIZER_COMMON_TESTS}/Sanitizer-i386-Test
(cd llvm_build64 && make -j$MAKE_JOBS check-sanitizer) || echo @@@STEP_FAILURE@@@
# Run unit test binaries in a single shard.
./llvm_build64/${SANITIZER_COMMON_TEST_BINARY_64}
./llvm_build64/${SANITIZER_COMMON_TEST_BINARY_32}

if [ "$PLATFORM" == "Linux" ]; then
  echo @@@BUILD_STEP run tests in ninja build tree@@@
  if [ ! -d llvm_build_ninja ]; then
    mkdir llvm_build_ninja
  fi
  CMAKE_NINJA_OPTIONS="${CMAKE_CLANG_OPTIONS} -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -G Ninja"
  (cd llvm_build_ninja && cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
      ${CMAKE_NINJA_OPTIONS} $LLVM_CHECKOUT)
  ln -sf llvm_build_ninja/compile_commands.json $LLVM_CHECKOUT
  (cd llvm_build_ninja && ninja check-asan) || echo @@@STEP_FAILURE@@@
  (cd llvm_build_ninja && ninja check-sanitizer) || echo @@@STEP_FAILURE@@@
  (cd llvm_build_ninja && ninja check-tsan) || echo @@@STEP_WARNINGS@@@
  (cd llvm_build_ninja && ninja check-ubsan) || echo @@@STEP_WARNINGS@@@
  (cd llvm_build_ninja && ninja check-msan) || echo @@@STEP_WARNINGS@@@
  (cd llvm_build_ninja && ninja check-lsan) || echo @@@STEP_WARNINGS@@@
fi

BUILD_ANDROID=${BUILD_ANDROID:-0}
if [ $BUILD_ANDROID == 1 ] ; then
    echo @@@BUILD_STEP build Android runtime and tests@@@
    ANDROID_TOOLCHAIN=$ROOT/../../../android-ndk/standalone
    ANDROID_BUILD_DIR=llvm_build64/android

    # Always clobber android build tree.
    # It has a hidden dependency on clang (through CXX) which is not known to
    # the build system.
    rm -rf $ANDROID_BUILD_DIR
    mkdir $ANDROID_BUILD_DIR
    (cd $ANDROID_BUILD_DIR && \
        cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
        -DLLVM_ANDROID_TOOLCHAIN_DIR=$ANDROID_TOOLCHAIN \
        -DCMAKE_TOOLCHAIN_FILE=$LLVM_CHECKOUT/cmake/platforms/Android.cmake \
        ${CMAKE_COMMON_OPTIONS} \
        $LLVM_CHECKOUT)
    (cd $ANDROID_BUILD_DIR && make -j$MAKE_JOBS \
        AsanUnitTests SanitizerUnitTests) || echo @@@STEP_FAILURE@@@
fi

RUN_ANDROID=${RUN_ANDROID:-0}
if [ $RUN_ANDROID == 1 ] ; then
    echo @@@BUILD_STEP reboot device@@@
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


    echo @@@BUILD_STEP run sanitizer_common tests [Android]@@@

    $ADB push $ANDROID_BUILD_DIR/projects/compiler-rt/lib/sanitizer_common/tests/SanitizerTest $DEVICE_ROOT/

    $ADB shell "$DEVICE_ROOT/SanitizerTest; \
        echo \$? >$DEVICE_ROOT/error_code"
    $ADB pull $DEVICE_ROOT/error_code error_code && (exit `cat error_code`) || echo @@@STEP_FAILURE@@@


    echo @@@BUILD_STEP run asan tests [Android]@@@

    ASAN_RT_LIB=libclang_rt.asan-arm-android.so
    ASAN_RT_LIB_PATH=`find $ANDROID_BUILD_DIR/lib -name $ASAN_RT_LIB`
    echo "ASan runtime: $ASAN_RT_LIB_PATH"
    $ADB push $ASAN_RT_LIB_PATH $DEVICE_ROOT/
    $ADB push $ANDROID_BUILD_DIR/projects/compiler-rt/lib/asan/tests/AsanTest $DEVICE_ROOT/

    NUM_SHARDS=7
    for ((SHARD=0; SHARD < $NUM_SHARDS; SHARD++)); do
        $ADB shell "LD_PRELOAD=$DEVICE_ROOT/$ASAN_RT_LIB \
          LD_LIBRARY_PATH=$DEVICE_ROOT \
          GTEST_TOTAL_SHARDS=$NUM_SHARDS \
          GTEST_SHARD_INDEX=$SHARD \
          $DEVICE_ROOT/AsanTest; \
          echo \$? >$DEVICE_ROOT/error_code"
        $ADB pull $DEVICE_ROOT/error_code error_code && echo && (exit `cat error_code`) || echo @@@STEP_FAILURE@@@
    done
fi
