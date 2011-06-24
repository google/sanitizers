#!/bin/bash

OS=`uname`
CXX=../../asan_clang_$OS/bin/clang++
SYMBOLIZER=../../scripts/asan_symbolize.py

for t in  *.tmpl; do
  for b in 32 64; do 
    c=`basename $t .tmpl`
    echo $b $c
    $CXX -g -m$b -fasan -O2 $c.cc
    ./a.out 2>&1 | $SYMBOLIZER | c++filt | ./match_output.py $t || exit 1
    rm ./a.out
  done
done
