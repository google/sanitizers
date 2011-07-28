#!/bin/bash

OS=`uname`
CXX=../../clang_build_$OS/Release+Asserts/bin/clang++
CXX_NATIVE=g++
SYMBOLIZER=../../scripts/asan_symbolize.py

for b in 32 64; do
  for O in 2 3; do
    $CXX -g -m$b -fasan -O$O shared-lib-main.cc -o shared-lib-main$b -ldl \
    -rdynamic
    $CXX -g -m$b -fasan -O$O shared-lib-so.cc -o shared-lib-so$b.so -shared -fPIC
#    $CXX_NATIVE -g -m$b -O$O shared-lib-main.cc -o shared-lib-main$b -ldl
#    $CXX_NATIVE -g -m$b -O$O shared-lib-so.cc -o shared-lib-so$b.so -shared -fPIC
  done
done
