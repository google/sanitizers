#!/bin/bash
SVN=http://llvm.org/svn/llvm-project
LLVM=$SVN/llvm/trunk
CFE=$SVN/cfe/trunk
COMPILER_RT=$SVN/compiler-rt/trunk
LIBCXX=$SVN/libcxx/trunk
LIBCXXABI=$SVN/libcxxabi/trunk

svn co $LLVM llvm
cd llvm
R=$(svn info | grep Revision: | awk '{print $2}')
(cd tools && svn co -r $R $CFE clang)
(cd projects && svn co -r $R $COMPILER_RT compiler-rt)
(cd projects && svn co -r $R $LIBCXX libcxx)
(cd projects && svn co -r $R $LIBCXXABI libcxxabi)
