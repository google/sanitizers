#!/bin/bash

OS=`uname`
CXX=../../clang_build_$OS/Release+Asserts/bin/clang++
SYMBOLIZER=../../scripts/asan_symbolize.py

for t in  *.tmpl; do
  for b in 32 64; do
    c=`basename $t .tmpl`
    exe=$c.$b
    $CXX -g -m$b -fasan -O2 $c.cc -o $exe
    ./$exe 2>&1 | $SYMBOLIZER 2> /dev/null | c++filt | ./match_output.py $t || exit 1
    echo $exe
    rm ./$exe
  done
done
