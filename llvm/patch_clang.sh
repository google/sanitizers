#!/bin/bash

ROOT=`pwd`
cd clang_src
patch -p 0 < $ROOT/llvm/clang.patch
cd lib/Transforms/Instrumentation
ln -s $ROOT/llvm/AddressSanitizer.cpp
ln -s $ROOT/asan/asan_rtl.h
ln -s $ROOT/third_party/tsan/common_util.cc
ln -s $ROOT/third_party/tsan/common_util.h
ln -s $ROOT/third_party/tsan/ignore.cc
ln -s $ROOT/third_party/tsan/ignore.h
ln -s $ROOT/third_party/tsan/ts_util.h

