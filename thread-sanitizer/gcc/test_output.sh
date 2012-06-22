#!/bin/bash

# You need to setup 2 envars:
# GCC_DIR=/gcc-4.6.1/install/lib/gcc/x86_64-unknown-linux-gnu/4.6.1/plugin/include
# TSAN_RT=/llvm/projects/compiler-rt/lib/tsan
# And add a correct gcc and FileCheck to PATH

ulimit -s 8192
set -e # fail on any error

make clean
make

ROOTDIR=$(dirname $0)

CC=gcc
CXX=gcc++
CFLAGS="-std=gnu99 -g -O1 -fPIE -fplugin=./libtsan.so"
LDFLAGS="-pie -lpthread -ldl $TSAN_RT/rtl/libtsan.a"

test_file() {
  SRC=$1
  COMPILER=$2
  echo ----- TESTING $(basename $1)
  OBJ=$SRC.o
  EXE=$SRC.exe
  $COMPILER $SRC $CFLAGS -c -o $OBJ
  $COMPILER $OBJ $LDFLAGS -o $EXE
  RES=$(TSAN_OPTIONS="atexit_sleep_ms=0" $EXE 2>&1 || true)
  if [ "$3" != "" ]; then
    printf "%s\n" "$RES"
  fi
  printf "%s\n" "$RES" | FileCheck $SRC
  if [ "$3" == "" ]; then
    rm -f $EXE $OBJ
  fi
}

if [ "$1" == "" ]; then
  for c in $TSAN_RT/output_tests/*.{c,cc}; do
    if [[ $c == */failing_* ]]; then
      echo SKIPPING FAILING TEST $c
      continue
    fi
    COMPILER=$CXX
    case $c in
      *.c) COMPILER=$CC
    esac
    test_file $c $COMPILER
  done
  wait
else
  test_file $TSAN_RT/output_tests/$1 $CXX "DUMP"
fi
