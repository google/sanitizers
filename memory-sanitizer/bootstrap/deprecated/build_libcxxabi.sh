#!/bin/bash

set -e

ARG=$1
shift

if [ "z$ARG" == "z--msan" ]; then
  CFLAGS="-fsanitize=memory -fsanitize-memory-track-origins"
  LDFLAGS="-fsanitize=memory -pie"
elif [ "z$ARG" != "z" ]; then
  echo "Unrecognized argument: $ARG"
  exit 1
fi

if ! [ -e LLVMBuild.txt ]; then
  echo "Please run me from LLVM source root."
  exit 1
fi

cd projects/libcxxabi/lib

LLVM=../../..
CLANG=$LLVM/build/bin/clang
CLANGXX=$LLVM/build/bin/clang++

CFLAGS="\
-g -O3 -fPIC \
-std=c++0x \
-fstrict-aliasing \
-Wstrict-aliasing=2 -Wsign-conversion -Wshadow -Wconversion -Wunused-variable \
-Wmissing-field-initializers -Wchar-subscripts -Wmismatched-tags \
-Wmissing-braces -Wshorten-64-to-32 -Wsign-compare -Wstrict-aliasing=2 \
-Wstrict-overflow=4 -Wunused-parameter -Wnewline-eof \
-I../include \
-I../../libcxx/include \
-I/usr/lib/gcc/x86_64-linux-gnu/4.6/include \
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
-o libc++abi.so.1.0 \
-shared \
-nodefaultlibs \
-Wl,-soname,libc++abi.so.1 \
-lpthread \
-lrt \
-lc \
$LDFLAGS \
"

echo "SOLINK libc++abi.so.1.0"

$CLANG $OBJS $LDFLAGS

echo "SYMLINKS"

ln -sf libc++abi.so.1.0 libc++abi.so.1
ln -sf libc++abi.so.1 libc++abi.so

echo "SUCCESS"
