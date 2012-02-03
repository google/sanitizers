#!/bin/bash

set -x
set -e
set -u


if [ "$BUILDBOT_CLOBBER" != "" ]; then
  echo @@@BUILD_STEP clobber@@@
  rm -rf llvm
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

echo @@@BUILD_STEP build llvm@@@
rm -rf llvm-build
mkdir llvm-build
cd llvm-build
../llvm/configure --enable-optimized
make -j$MAKE_JOBS

echo @@@BUILD_STEP test llvm@@@
make check-all || echo @@@STEP_WARNINGS@@@

echo @@@BUILD_STEP build asan@@@
CLANG_BUILD=`pwd`/Release+Asserts
cd ../llvm/projects/compiler-rt/lib/asan/
make -f Makefile.old CLANG_BUILD=$CLANG_BUILD get_third_party
make -f Makefile.old CLANG_BUILD=$CLANG_BUILD -j$MAKE_JOBS

echo @@@BUILD_STEP asan test32@@@
make -f Makefile.old CLANG_BUILD=$CLANG_BUILD t32  || echo @@@STEP_FAILURE@@@

echo @@@BUILD_STEP asan test64@@@
make -f Makefile.old CLANG_BUILD=$CLANG_BUILD t64  || echo @@@STEP_FAILURE@@@

echo @@@BUILD_STEP asan output_tests@@@
make -f Makefile.old CLANG_BUILD=$CLANG_BUILD output_tests  || echo @@@STEP_FAILURE@@@
