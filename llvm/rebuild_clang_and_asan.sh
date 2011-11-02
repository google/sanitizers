#!/bin/bash
OS=`uname`
DIR=clang_build_$OS
JOBS=-j16
if [ "$OS" == "Darwin" ]
then
  JOBS=-j`sysctl -n hw.logicalcpu`
fi
(cd $DIR/lib/Transforms/Instrumentation/ && make $JOBS ENABLE_OPTIMIZED=1) && \
(cd $DIR/tools/clang/ && make $JOBS ENABLE_OPTIMIZED=1)
