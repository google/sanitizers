#!/bin/bash

set -x
set -e
set -u

HERE="$(cd $(dirname $0) && pwd)"
. ${HERE}/buildbot_functions.sh

ROOT=`pwd`
PLATFORM=`uname`
# for CMake
export PATH="/usr/local/bin:$PATH"

LLVM_CHECKOUT=$ROOT/llvm
CLANG_BUILD=$ROOT/clang_build
CHROME_CHECKOUT=$ROOT/chrome
##ASAN_TESTS="base_unittests net_unittests remoting_unittests media_unittests unit_tests browser_tests content_browsertests"
TESTS_NO_SANDBOX="base_unittests cacheinvalidation_unittests cc_unittests cast_unittests crypto_unittests gpu_unittests url_unittests jingle_unittests device_unittests net_unittests ppapi_unittests printing_unittests ipc_tests sync_unit_tests sql_unittests ui_unittests content_unittests remoting_unittests media_unittests unit_tests"
TESTS_MAYBE_SANDBOX="browser_tests content_browsertests"
TESTS_NEED_SANDBOX="sandbox_linux_unittests"
CHROME_TESTS="${TESTS_NO_SANDBOX} ${TESTS_MAYBE_SANDBOX} ${TESTS_NEED_SANDBOX}"

type -a gcc
type -a g++
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
ninja clang_rt.asan-x86_64 clang_rt.asan-i386 llvm-symbolizer compiler-rt-headers || echo @@@STEP_FAILURE@@@
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

export GYP_DEFINES="use_aura=1 clang_use_chrome_plugins=0 asan=1 linux_use_tcmalloc=0  component=static_library lsan=1"
export GYP_GENERATORS=ninja
export ASAN_BIN=$CLANG_BUILD/bin
export CC="$ASAN_BIN/clang"
export CXX="$ASAN_BIN/clang++"

gclient runhooks
)

echo @@@BUILD_STEP clean Chromium build@@@
(
cd $CHROME_CHECKOUT/src
ninja -C out/Release $CHROME_TESTS
)

set_chrome_suid_sandbox
export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu/debug

GTEST_FLAGS="--brave-new-test-launcher --test-launcher-bot-mode --test-launcher-batch-limit=1 --verbose --test-launcher-print-test-stdio=always --gtest_print_time"
for test_name in ${TESTS_NO_SANDBOX} ${TESTS_MAYBE_SANDBOX}
do
  echo @@@BUILD_STEP running $test_name under ASan + LSan@@@
  (
    set +x
    cd $CHROME_CHECKOUT/src
    export LLVM_SYMBOLIZER_PATH=$CLANG_BUILD/bin/llvm-symbolizer
    # See http://dev.chromium.org/developers/testing/addresssanitizer for the
    # instructions to run ASan.
    export ASAN_OPTIONS="strict_memcmp=0 replace_intrin=0 detect_leaks=1"
    export LSAN_OPTIONS="verbosity=1:suppressions=tools/lsan/suppressions.txt"
    export ASAN_SYMBOLIZER_PATH="${LLVM_SYMBOLIZER_PATH}"
    # Without --server-args="-screen 0 1024x768x24" at least some of the Chrome
    # tests hang: http://crbug.com/242486
    xvfb-run --server-args="-screen 0 1024x768x24" out/Release/$test_name ${GTEST_FLAGS} --no-sandbox || echo @@@STEP_FAILURE@@@
    ##((${PIPESTATUS[0]})) && echo @@@STEP_FAILURE@@@ || true
  )
done

GTEST_FLAGS="--brave-new-test-launcher --test-launcher-bot-mode --test-launcher-batch-limit=1 --verbose --test-launcher-print-test-stdio=always --gtest_print_time"
for test_name in ${TESTS_MAYBE_SANDBOX} ${TESTS_NEED_SANDBOX}
do
  echo @@@BUILD_STEP running $test_name under ASan w/ sandbox@@@
  (
    set +x
    cd $CHROME_CHECKOUT/src
    set_chrome_suid_sandbox
    export LLVM_SYMBOLIZER_PATH=$CLANG_BUILD/bin/llvm-symbolizer
    # See http://dev.chromium.org/developers/testing/addresssanitizer for the
    # instructions to run ASan.
    export ASAN_OPTIONS="strict_memcmp=0 replace_intrin=0 symbolize=false"
    # Without --server-args="-screen 0 1024x768x24" at least some of the Chrome
    # tests hang: http://crbug.com/242486
    xvfb-run --server-args="-screen 0 1024x768x24" out/Release/$test_name ${GTEST_FLAGS} 2>&1 | tools/valgrind/asan/asan_symbolize.py | c++filt 
    ((${PIPESTATUS[0]})) && echo @@@STEP_FAILURE@@@ || true
  )
done
