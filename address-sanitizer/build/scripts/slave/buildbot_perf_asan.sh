#!/bin/bash

set -x
set -e
set -u

HERE="$(cd $(dirname $0) && pwd)"
. ${HERE}/buildbot_functions.sh

ROOT=`pwd`
PLATFORM=`uname`
export PATH="/usr/local/bin:$PATH"

LLVM_CHECKOUT=$ROOT/llvm
CLANG_BUILD=$ROOT/clang_build
SPEC_DIRNAME=SPEC_CPU2006v1.2
SPEC_SRC="${ROOT}/${SPEC_DIRNAME}"
SPEC_RUNNER=./run_spec_clang_asan.sh
#SPEC_TESTS='perlbench bzip2'
SPEC_TESTS='perlbench bzip2 gcc mcf gobmk hmmer sjeng libquantum h264ref omnetpp astar xalancbmk'

CMAKE_COMMON_OPTIONS="-GNinja -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_ASSERTIONS=ON"

echo @@@BUILD_STEP update@@@
buildbot_update

# LLVM build requires ninja.
# TODO(glider): make a common function to fetch ninja.

echo @@@BUILD_STEP fetch depot_tools@@@
(
  cd $ROOT
  if [ ! -d depot_tools ]; then
    git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
  fi
)
export PATH="$ROOT/depot_tools:$PATH"

echo @@@BUILD_STEP build fresh clang@@@
(
if [ ! -d $CLANG_BUILD ]; then
  mkdir $CLANG_BUILD
fi
cd $CLANG_BUILD
export PATH="$PATH:$ROOT/../../../ninja"
cmake -DCMAKE_BUILD_TYPE=Release ${CMAKE_COMMON_OPTIONS} $LLVM_CHECKOUT
ninja clang || echo @@@STEP_FAILURE@@@
# TODO(glider): build other targets depending on the platform.
# See https://code.google.com/p/address-sanitizer/wiki/HowToBuild.
ninja clang_rt.asan-x86_64 clang_rt.asan-i386
)


echo @@@BUILD_STEP unpack, patch and install SPEC@@@
(
cd $ROOT
if [ ! -d $SPEC_SRC ]; then
  (
  tar -jxf "$ROOT/../../../SPEC/${SPEC_DIRNAME}.tar.bz2"
  cd $SPEC_SRC
  wget https://address-sanitizer.googlecode.com/svn/trunk/spec/spec2006-asan.patch
  yes | ./install.sh
  patch -p1 -i spec2006-asan.patch
  )
fi

if [ ! -e $SPEC_SRC/$SPEC_RUNNER ]; then
  (
  cd $SPEC_SRC
  wget https://address-sanitizer.googlecode.com/svn/trunk/spec/run_spec_clang_asan.sh
  chmod a+x $SPEC_RUNNER
  )
fi
)

export ASAN_BIN=$CLANG_BUILD/bin
#export CC="$ASAN_BIN/clang"
#export CXX="$ASAN_BIN/clang++"
export PATH="$ASAN_BIN:$PATH"

for test_name in $SPEC_TESTS
do
  echo @@@BUILD_STEP running $test_name@@@
  (
    set +x
    cd $SPEC_SRC
    name=asan-spec
    size=test
    SPEC_WRAPPER="perf record -q -o `pwd`/perf.data" $SPEC_RUNNER $name $size $test_name 2>&1 | tee asan-$test_name.log
    grep "ERROR: AddressSanitizer" asan-$test_name.log && echo @@@STEP_FAILURE@@@
    perf report
  )
done
