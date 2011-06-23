#!/bin/bash
cd clang_src
ROOT=..
patch -p 0 < $ROOT/llvm/clang.patch
cd lib/Transforms/Instrumentation
ROOT=../../../..
ln -fs $ROOT/llvm/AddressSanitizer.cpp
ln -fs $ROOT/asan/asan_rtl.h
ln -fs $ROOT/third_party/tsan/common_util.cc
ln -fs $ROOT/third_party/tsan/common_util.h
ln -fs $ROOT/third_party/tsan/ignore.cc
ln -fs $ROOT/third_party/tsan/ignore.h
ln -fs $ROOT/third_party/tsan/ts_util.h

