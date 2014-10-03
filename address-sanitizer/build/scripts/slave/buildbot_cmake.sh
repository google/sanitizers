#!/bin/bash

set -x
set -e
set -u

# dump buildbot env
env

HERE="$(dirname $0)"
. ${HERE}/buildbot_functions.sh

if [ $BUILD_ANDROID == 1 -o $RUN_ANDROID == 1 ] ; then
  . ${HERE}/buildbot_android_functions.sh
  trap "android_emulator_cleanup" EXIT
fi

ROOT=`pwd`
PLATFORM=`uname`
ARCH=`uname -m`
export PATH="/usr/local/bin:$PATH"
export ANDROID_SDK_HOME=$ROOT/../../..

if [ "$BUILDBOT_CLOBBER" != "" ]; then
  echo @@@BUILD_STEP clobber@@@
  rm -rf llvm
  rm -rf clang_build
fi

# Always clobber bootstrap build trees.
rm -rf compiler_rt_build
rm -rf llvm_build64
rm -rf llvm_build_ninja

SUPPORTS_32_BITS=${SUPPORTS_32_BITS:-1}
MAKE_JOBS=${MAX_MAKE_JOBS:-16}
LLVM_CHECKOUT=$ROOT/llvm
COMPILER_RT_CHECKOUT=$LLVM_CHECKOUT/projects/compiler-rt
CMAKE_COMMON_OPTIONS="-DLLVM_ENABLE_ASSERTIONS=ON"
ENABLE_LIBCXX_FLAG=
if [ "$PLATFORM" == "Darwin" ]; then
  CMAKE_COMMON_OPTIONS="${CMAKE_COMMON_OPTIONS} -DPYTHON_EXECUTABLE=/usr/bin/python"
  ENABLE_LIBCXX_FLAG="-DLLVM_ENABLE_LIBCXX=ON"
fi

echo @@@BUILD_STEP update@@@
buildbot_update


echo @@@BUILD_STEP lint@@@
CHECK_LINT=${COMPILER_RT_CHECKOUT}/lib/sanitizer_common/scripts/check_lint.sh
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

# If we're building with libcxx, install the headers to clang_build/include.
if [ ! -z ${ENABLE_LIBCXX_FLAG} ]; then
(cd clang_build && make -C ${LLVM_CHECKOUT}/projects/libcxx installheaders \
  HEADER_DIR=${PWD}/include) || echo @@@STEP_FAILURE@@@
fi

# Do a sanity check on Linux: build and test sanitizers using gcc as a host
# compiler.
# if [ "$PLATFORM" == "Linux" ]; then
#   echo @@@BUILD_STEP run sanitizer tests in gcc build@@@
#   (cd clang_build && make -j$MAKE_JOBS check-sanitizer) || echo @@@STEP_FAILURE@@@
#   (cd clang_build && make -j$MAKE_JOBS check-asan) || echo @@@STEP_FAILURE@@@
#   (cd clang_build && make -j$MAKE_JOBS check-lsan) || echo @@@STEP_FAILURE@@@
#   (cd clang_build && make -j$MAKE_JOBS check-msan) || echo @@@STEP_FAILURE@@@
#   (cd clang_build && make -j$MAKE_JOBS check-tsan) || echo @@@STEP_FAILURE@@@
#   (cd clang_build && make -j$MAKE_JOBS check-ubsan) || echo @@@STEP_WARNINGS@@@
#   (cd clang_build && make -j$MAKE_JOBS check-dfsan) || echo @@@STEP_WARNINGS@@@
# fi

### From now on we use just-built Clang as a host compiler ###
CLANG_PATH=${ROOT}/clang_build/bin
# Build self-hosted tree with fresh Clang and -Werror.
CMAKE_CLANG_OPTIONS="${CMAKE_COMMON_OPTIONS} -DLLVM_ENABLE_WERROR=ON -DCMAKE_C_COMPILER=${CLANG_PATH}/clang -DCMAKE_CXX_COMPILER=${CLANG_PATH}/clang++"
BUILD_TYPE=Release

echo @@@BUILD_STEP bootstrap clang@@@
if [ ! -d llvm_build64 ]; then
  mkdir llvm_build64
fi
(cd llvm_build64 && cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
    ${CMAKE_CLANG_OPTIONS} -DLLVM_BUILD_EXTERNAL_COMPILER_RT=ON \
    ${ENABLE_LIBCXX_FLAG} $LLVM_CHECKOUT)
# First, build only Clang.
(cd llvm_build64 && make -j$MAKE_JOBS clang) || echo @@@STEP_FAILURE@@@

# If needed, install the headers to clang_build/include.
if [ ! -z ${ENABLE_LIBCXX_FLAG} ]; then
(cd llvm_build64 && make -C ${LLVM_CHECKOUT}/projects/libcxx installheaders \
  HEADER_DIR=${PWD}/include) || echo @@@STEP_FAILURE@@@
fi

# Now build everything else.
(cd llvm_build64 && make -j$MAKE_JOBS) || echo @@@STEP_FAILURE@@@
FRESH_CLANG_PATH=${ROOT}/llvm_build64/bin
COMPILER_RT_BUILD_PATH=projects/compiler-rt/src/compiler-rt-build

echo @@@BUILD_STEP run asan tests@@@
(cd llvm_build64 && make -j$MAKE_JOBS check-asan) || echo @@@STEP_FAILURE@@@

if [ "$PLATFORM" == "Linux" -a "$ARCH" == "x86_64" ]; then
  echo @@@BUILD_STEP run msan unit tests@@@
  (cd llvm_build64 && make -j$MAKE_JOBS check-msan) || echo @@@STEP_FAILURE@@@
fi

if [ "$PLATFORM" == "Linux" -a "$ARCH" == "x86_64" ]; then
  echo @@@BUILD_STEP run 64-bit tsan unit tests@@@
  (cd llvm_build64 && make -j$MAKE_JOBS check-tsan) || echo @@@STEP_FAILURE@@@
fi

if [ "$PLATFORM" == "Linux" -a "$ARCH" == "x86_64" ]; then
  echo @@@BUILD_STEP run 64-bit lsan unit tests@@@
  (cd llvm_build64 && make -j$MAKE_JOBS check-lsan) || echo @@@STEP_FAILURE@@@
fi

echo @@@BUILD_STEP run sanitizer_common tests@@@
(cd llvm_build64 && make -j$MAKE_JOBS check-sanitizer) || echo @@@STEP_FAILURE@@@

echo @@@BUILD_STEP build standalone compiler-rt@@@
if [ ! -d compiler_rt_build ]; then
  mkdir compiler_rt_build
fi
(cd compiler_rt_build && cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
  -DCMAKE_C_COMPILER=${FRESH_CLANG_PATH}/clang \
  -DCMAKE_CXX_COMPILER=${FRESH_CLANG_PATH}/clang++ \
  -DCOMPILER_RT_INCLUDE_TESTS=ON \
  -DCOMPILER_RT_ENABLE_WERROR=ON \
  -DLLVM_CONFIG_PATH=${FRESH_CLANG_PATH}/llvm-config \
  $COMPILER_RT_CHECKOUT)
(cd compiler_rt_build && make -j$MAKE_JOBS) || echo @@@STEP_FAILURE@@@

echo @@@BUILD_STEP test standalone compiler-rt@@@
(cd compiler_rt_build && make -j$MAKE_JOBS check-all) || echo @@@STEP_FAILURE@@@

HAVE_NINJA=${HAVE_NINJA:-1}
if [ "$PLATFORM" == "Linux" -a $HAVE_NINJA == 1 ]; then
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
  (cd llvm_build_ninja && ninja check-tsan) || echo @@@STEP_FAILURE@@@
  (cd llvm_build_ninja && ninja check-msan) || echo @@@STEP_FAILURE@@@
  (cd llvm_build_ninja && ninja check-lsan) || echo @@@STEP_FAILURE@@@
  (cd llvm_build_ninja && ninja check-ubsan) || echo @@@STEP_WARNINGS@@@
  (cd llvm_build_ninja && ninja check-dfsan) || echo @@@STEP_WARNINGS@@@
fi

BUILD_ANDROID=${BUILD_ANDROID:-0}
if [ $BUILD_ANDROID == 1 ] ; then
    echo @@@BUILD_STEP build Android runtime and tests@@@

    build_compiler_rt arm arm-linux-androideabi
    build_llvm_symbolizer arm arm-linux-androideabi
    
    build_compiler_rt x86 i686-linux-android
    build_llvm_symbolizer x86 i686-linux-android
fi

RUN_ANDROID=${RUN_ANDROID:-0}
if [ $RUN_ANDROID == 1 ] ; then
    test_android arm arm-K
fi
