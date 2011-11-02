#!/bin/bash
OS=`uname`
DIR=clang_build_$OS
JOBS=-j16
if [ "$OS" == "Darwin" ]
then
  JOBS=-j`sysctl -n hw.logicalcpu`
fi
rm -rf $DIR
mkdir -p $DIR
cd $DIR
../clang_src/configure --enable-optimized
make $JOBS

