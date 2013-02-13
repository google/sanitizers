#!/bin/bash

set -x
set -e
set -u

. buildbot_functions.sh

ROOT=`pwd`
PLATFORM=`uname`
export PATH="/usr/local/bin:$PATH"

if [ "$BUILDBOT_CLOBBER" != "" ]; then
  echo @@@BUILD_STEP clobber@@@
  rm -rf llvm
  rm -rf llvm_build0
  rm -rf llvm_build_msan
fi

MAKE_JOBS=${MAX_MAKE_JOBS:-16}
LLVM_CHECKOUT=$ROOT/llvm

CMAKE_COMMON_OPTIONS="-GNinja -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_ASSERTIONS=ON"
CMAKE_STAGE1_OPTIONS="${CMAKE_COMMON_OPTIONS}"

echo @@@BUILD_STEP update@@@
buildbot_update


echo @@@BUILD_STEP build stage1 clang@@@
if [ ! -d llvm_build0 ]; then
  mkdir llvm_build0
fi
(cd llvm_build0 && cmake ${CMAKE_OPTIONS} $LLVM_CHECKOUT && ninja) || \
  echo @@@STEP_FAILURE@@@

CMAKE_STAGE2_COMMON_OPTIONS="${CMAKE_COMMON_OPTIONS} -DLLVM_ENABLE_WERROR=ON"
CMAKE_MSAN_OPTIONS="${CMAKE_STAGE2_COMMON_OPTIONS} -DCMAKE_C_COMPILER=${CLANG_PATH}/clang -DCMAKE_CXX_COMPILER=${CLANG_PATH}/clang++"
