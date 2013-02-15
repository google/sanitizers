#!/bin/bash

set -e

ARG=$1
shift

if [ "z$ARG" == "z--msan-origins" ]; then
  CFLAGS="-fsanitize=memory"
  LDFLAGS="-fsanitize=memory -pie"
  ARG=$1
  shift
elif [ "z$ARG" == "z--msan" ]; then
  CFLAGS="-fsanitize=memory -fsanitize-memory-track-origins"
  LDFLAGS="-fsanitize=memory -pie"
  ARG=$1
  shift
fi

if [ "z$ARG" == "z" ]; then
  echo "Usage: $0 [--msan] llvmsrcpath"
  exit 1
fi

LLVM=$ARG

if [ "z$LLVM_BIN" == "z" ]; then
  echo "Please set \$LLVM_BIN to the location of msan-enabled 'clang' binary."
  exit 1
fi

CLANG=$LLVM_BIN/clang
CLANGXX=$LLVM_BIN/clang++

LIBCXXABI=$LLVM/projects/libcxxabi
LIBCXX=$LLVM/projects/libcxx

# Build libcxxabi.

LIBCXXABI_CFLAGS="\
-g -O3 -fPIC \
-std=c++0x \
-fstrict-aliasing \
-Wstrict-aliasing=2 -Wsign-conversion -Wshadow -Wconversion -Wunused-variable \
-Wmissing-field-initializers -Wchar-subscripts -Wmismatched-tags \
-Wmissing-braces -Wshorten-64-to-32 -Wsign-compare -Wstrict-aliasing=2 \
-Wstrict-overflow=4 -Wunused-parameter -Wnewline-eof \
-I${LIBCXXABI}/include \
-I${LIBCXX}/include \
-I/usr/lib/gcc/x86_64-linux-gnu/4.6/include \
$CFLAGS \
"

LIBCXXABI_OBJS=
for source in ${LIBCXXABI}/src/*.cpp; do
    obj=$(basename ${source%.cpp}.o)
    echo "CXX $obj"
    $CLANGXX -c $LIBCXXABI_CFLAGS $source
    LIBCXXABI_OBJS="$LIBCXXABI_OBJS $obj"
done

LIBCXXABI_LDFLAGS="\
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

$CLANG $LIBCXXABI_OBJS $LIBCXXABI_LDFLAGS

echo "SYMLINKS"

ln -sf libc++abi.so.1.0 libc++abi.so.1
ln -sf libc++abi.so.1 libc++abi.so

# Now build libcxx.

LIBCXX_CFLAGS="\
-g -Os -fPIC \
-std=c++0x \
-fstrict-aliasing \
-Wall -Wextra -Wshadow -Wconversion -Wnewline-eof -Wpadded \
-Wmissing-prototypes -Wstrict-aliasing=2 -Wstrict-overflow=4 \
-nostdinc++ \
-I${LIBCXXABI}/include \
-I${LIBCXX}/include \
$CFLAGS \
"

LIBCXX_OBJS=
for source in ${LIBCXX}/src/*.cpp; do
    obj=$(basename ${source%.cpp}.o)
    echo "CXX $obj"
    $CLANGXX -c $LIBCXX_CFLAGS $source
    LIBCXX_OBJS="$LIBCXX_OBJS $obj"
done

LIBCXX_LDFLAGS="\
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

$CLANG $LIBCXX_OBJS $LIBCXX_LDFLAGS

ln -sf libc++.so.1.0 libc++.so.1
ln -sf libc++.so.1 libc++.so

echo "SUCCESS"
