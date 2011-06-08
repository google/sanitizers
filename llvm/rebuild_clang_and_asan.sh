#!/bin/bash
OS=`uname`
DIR=clang_build_$OS
(cd $DIR/lib/Transforms/Instrumentation/ && make -j16 ENABLE_OPTIMIZED=1) && \
(cd $DIR/tools/clang/ && make -j16 ENABLE_OPTIMIZED=1)
