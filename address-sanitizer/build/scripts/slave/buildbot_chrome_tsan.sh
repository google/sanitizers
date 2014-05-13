#!/bin/bash

# TODO(glider): merge this with buildbot_chrome_asan.sh

set -x
# set -e # terminate if someone returns 1
set -u

HERE="$(cd $(dirname $0) && pwd)"
. ${HERE}/buildbot_functions.sh

ROOT=`pwd`
PLATFORM=`uname`
# for CMake
export PATH="/usr/local/bin:$PATH"
export PATH="/usr/local/gcc-4.8.2/bin:$PATH"
export LD_LIBRARY_PATH=$GCC_BUILD/lib64

LLVM_CHECKOUT=$ROOT/llvm
CLANG_BUILD=$ROOT/clang_build
CHROME_CHECKOUT=$ROOT/chrome
CHROME_TESTS="base_unittests net_unittests remoting_unittests media_unittests unit_tests browser_tests content_browsertests cast_unittests"
#CHROME_TESTS="base_unittests net_unittests"

CMAKE_COMMON_OPTIONS="-GNinja -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_ASSERTIONS=ON"

echo @@@BUILD_STEP update@@@
buildbot_update

# Chrome builder requires depot_tools to be present in $PATH.
# LLVM build also requires ninja.

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
cmake -DCMAKE_BUILD_TYPE=Release ${CMAKE_COMMON_OPTIONS} \
  -DCMAKE_C_COMPILER=$(which gcc) -DCMAKE_CXX_COMPILER=$(which g++) \
  $LLVM_CHECKOUT
ninja clang || echo @@@STEP_FAILURE@@@
# TODO(glider): build other targets depending on the platform.
# See https://code.google.com/p/address-sanitizer/wiki/HowToBuild.
ninja clang_rt.tsan-x86_64 llvm-symbolizer compiler-rt-headers || echo @@@STEP_FAILURE@@@
)


echo @@@BUILD_STEP check out Chromium@@@
(
if [ ! -d $CHROME_CHECKOUT ]; then
  mkdir $CHROME_CHECKOUT
fi

cd $CHROME_CHECKOUT

if [ ! -e .gclient ]; then
  gclient config https://chromium.googlesource.com/chromium/src.git --git-deps
  gclient sync --nohooks
fi

# Sync to LKGR, see http://crbug.com/109191
mv .gclient .gclient-tmp
cat .gclient-tmp  | \
    sed 's/"safesync_url": ""/"safesync_url": "https:\/\/chromium-status.appspot.com\/git-lkgr"/' > .gclient
rm .gclient-tmp

gclient sync --nohooks
)

echo @@@BUILD_STEP gclient runhooks@@@
(
cd $CHROME_CHECKOUT/src

# Clobber Chromium to catch possible LLVM regressions early.
rm -rf out/Release

# See http://dev.chromium.org/developers/testing/threadsanitizer-tsan-v2
export COMMON_GYP_DEFINES="use_allocator=none use_aura=1 clang_use_chrome_plugins=0 component=static_library"
export GYP_DEFINES="tsan=1 disable_nacl=1 $COMMON_GYP_DEFINES"
export GYP_GENERATORS=ninja
export CLANG_BIN=$CLANG_BUILD/bin
export CC="$CLANG_BIN/clang"
export CXX="$CLANG_BIN/clang++"

gclient runhooks
)

echo @@@BUILD_STEP clean Chromium build@@@
(
cd $CHROME_CHECKOUT/src
export TSAN_OPTIONS=report_thread_leaks=0  # suppress reports in the host binaries
ninja -C out/Release $CHROME_TESTS
) || exit 1

GTEST_FLAGS="--brave-new-test-launcher --test-launcher-bot-mode --test-launcher-batch-limit=1 --verbose --test-launcher-print-test-stdio=always --gtest_print_time"
for test_name in $CHROME_TESTS
do
  echo @@@BUILD_STEP running $test_name@@@
  (
    set -e
    cd $CHROME_CHECKOUT/src
    # See http://dev.chromium.org/developers/testing/threadsanitizer-tsan-v2
    # for the instructions to run TSan.
    export TSAN_OPTIONS="history_size=7 external_symbolizer_path=third_party/llvm-build/Release+Asserts/bin/llvm-symbolizer suppressions=tools/valgrind/tsan_v2/suppressions.txt report_signal_unsafe=0 report_thread_leaks=0" 
    # Without --server-args="-screen 0 1024x768x24" at least some of the Chrome
    # tests hang: http://crbug.com/242486
    xvfb-run --server-args="-screen 0 1024x768x24" out/Release/$test_name ${GTEST_FLAGS} --no-sandbox --child-clean-exit 2>&1
    ((${PIPESTATUS[0]})) && echo @@@STEP_FAILURE@@@ || true
  )
done
