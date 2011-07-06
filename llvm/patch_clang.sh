#!/bin/bash
cd clang_src
ROOT=..
patch -p 0 < $ROOT/llvm/clang.patch
cd lib/Transforms/Instrumentation
ROOT=../../../..
ln -fs $ROOT/llvm/AddressSanitizer.cpp
