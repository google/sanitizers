#!/bin/bash

set -x
set -e
set -u


echo @@@BUILD_STEP clobber@@@
rm -rf llvm-build

echo @@@BUILD_STEP update@@@
if [ "x$BUILDBOT_CLOBBER" != "x" ]; then
  rm -rf llvm
fi

REV_ARG=
if [ "x$BUILDBOT_REVISION" != "x" ]; then
  REV_ARG="-r$BUILDBOT_REVISION"
fi

if [ -d llvm ]; then
  svn up llvm $REV_ARG
  if [ "x$REV_ARG" == "x" ]; then
    REV_ARG="-r"$(svn info llvm | grep '^Revision:' | awk '{print $2}')
  fi
  svn up llvm/tools/clang $REV_ARG
  svn up llvm/projects/compiler-rt $REV_ARG
else
  svn co http://llvm.org/svn/llvm-project/llvm/trunk llvm $REV_ARG
  if [ "x$REV_ARG" == "x" ]; then
    REV_ARG="-r"$(svn info llvm | grep '^Revision:' | awk '{print $2}')
  fi
  svn co http://llvm.org/svn/llvm-project/cfe/trunk llvm/tools/clang $REV_ARG
  svn co http://llvm.org/svn/llvm-project/compiler-rt/trunk llvm/projects/compiler-rt $REV_ARG
fi

echo @@@BUILD_STEP build llvm@@@
mkdir llvm-build
cd llvm-build
../llvm/configure --enable-optimized
make -j16

echo @@@BUILD_STEP test llvm@@@
make check-all || echo @@@STEP_FAILURE@@@

echo @@@BUILD_STEP build asan@@@
CLANG_BUILD=`pwd`/Release+Asserts
cd ../llvm/projects/compiler-rt/lib/asan/
make -f Makefile.old CLANG_BUILD=$CLANG_BUILD get_third_party
make -f Makefile.old CLANG_BUILD=$CLANG_BUILD -j16

echo @@@BUILD_STEP test asan@@@
make -f Makefile.old CLANG_BUILD=$CLANG_BUILD test  || echo @@@STEP_FAILURE@@@
