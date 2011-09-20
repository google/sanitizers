#!/bin/bash
export THISDIR=`dirname $0`
. $THISDIR/config.sh
svn co -r$LLVM_REV http://llvm.org/svn/llvm-project/llvm/trunk clang_src
cd clang_src/tools
svn co -r$LLVM_REV http://llvm.org/svn/llvm-project/cfe/trunk clang

