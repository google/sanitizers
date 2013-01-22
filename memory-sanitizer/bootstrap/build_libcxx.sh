#!/bin/bash

set -e

if ! [ -e LLVMBuild.txt ]; then
  echo "Please run me from LLVM source root."
  exit 1
fi

cd projects/libcxx/lib

LLVM=../../..
CLANG=$LLVM/build/bin/clang
CLANGXX=$LLVM/build/bin/clang++

CFLAGS="\
-g -Os -fPIC \
-std=c++0x \
-fstrict-aliasing \
-Wall -Wextra -Wshadow -Wconversion -Wnewline-eof -Wpadded \
-Wmissing-prototypes -Wstrict-aliasing=2 -Wstrict-overflow=4 \
-nostdinc++ \
-I../include \
-I../../libcxxabi/include \
$CFLAGS \
"

OBJS=
for source in ../src/*.cpp; do
    obj=$(basename ${source%.cpp}.o)
    echo "CXX $obj"
    $CLANGXX -c $CFLAGS $source
    OBJS="$OBJS $obj"
done

LDFLAGS="\
-o libc++.so.1.0 \
-shared \
-nodefaultlibs \
-Wl,-soname,libc++.so.1 \
-lpthread \
-lrt \
-lc \
$LDFLAGS \
"

echo "SOLINK libc++.so.1.0"

$CLANG $OBJS $LDFLAGS

echo "SYMLINKS"

ln -sf libc++.so.1.0 libc++.so.1
ln -sf libc++.so.1 libc++.so

echo "SUCCESS"
