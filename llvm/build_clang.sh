#!/bin/bash
OS=`uname`
DIR=clang_build_$OS
rm -rf $DIR
mkdir -p $DIR
cd $DIR
../clang_src/configure --enable-optimized
make -j ${J:-16}

