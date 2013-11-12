#!/bin/bash

set -e

LLVM=$1

if [ "z$LLVM_BIN" == "z" ]; then
  echo "Please set \$LLVM_BIN to the location of msan-enabled 'clang' binary."
  exit 1
fi

CLANG=$LLVM_BIN/clang
CLANGXX=$LLVM_BIN/clang++
ARFLAGS="--plugin ${LLVM_BIN}/../lib/LLVMgold.so"

LIBCXXABI=$LLVM/projects/libcxxabi
LIBCXX=$LLVM/projects/libcxx

GCC_INCLUDE=$(echo | g++ -Wp,-v -x c++ - -fsyntax-only 2>&1 | grep '^ /usr/lib/gcc.*include$' | tr -d ' ')

# Build libcxxabi.
# Since libcxxabi does not have a proper build system, we do everything in this script.
# The flags below match those used in the official "lib/buildit" script.
LIBCXXABI_CFLAGS="\
-O3 -fPIC \
-std=c++0x \
-fstrict-aliasing \
-Wstrict-aliasing=2 -Wsign-conversion -Wshadow -Wconversion -Wunused-variable \
-Wmissing-field-initializers -Wchar-subscripts -Wmismatched-tags \
-Wmissing-braces -Wshorten-64-to-32 -Wsign-compare -Wstrict-aliasing=2 \
-Wstrict-overflow=4 -Wno-unused-parameter -Wnewline-eof \
-I${LIBCXXABI}/include \
-I${LIBCXX}/include \
-I${GCC_INCLUDE} \
$LIBCXXABI_CFLAGS \
$CFLAGS \
"

LIBCXXABI_OBJS=
for source in ${LIBCXXABI}/src/*.cpp; do
    obj=$(basename ${source%.cpp}.o)
    echo "CXX $obj"
    $CLANGXX -c $LIBCXXABI_CFLAGS $source
    LIBCXXABI_OBJS="$LIBCXXABI_OBJS $obj"
done

echo "AR libc++abi.a"

ar rc $ARFLAGS libc++abi.a $LIBCXXABI_OBJS

# Now build libcxx.
LIBCXX_CFLAGS="\
-Os -fPIC \
-std=c++0x \
-fstrict-aliasing \
-Wall -Wextra -Wshadow -Wconversion -Wnewline-eof -Wpadded \
-Wno-missing-prototypes -Wstrict-aliasing=2 -Wstrict-overflow=4 \
-Wno-unused-parameter \
-nostdinc++ \
-I${LIBCXXABI}/include \
-I${LIBCXX}/include \
$LIBCXX_CFLAGS \
$CFLAGS \
"

LIBCXX_OBJS=
for source in ${LIBCXX}/src/*.cpp; do
    obj=$(basename ${source%.cpp}.o)
    echo "CXX $obj"
    $CLANGXX -c $LIBCXX_CFLAGS $source
    LIBCXX_OBJS="$LIBCXX_OBJS $obj"
done

echo "AR libc++abi.a"

ar rc $ARFLAGS libc++.a $LIBCXX_OBJS

echo "INSTALL"

mkdir lib
cp libc++abi.a libc++.a lib/

echo "COPY HEADERS"

tar --exclude-vcs -cf - -C $LIBCXXABI include | tar -xf -
tar --exclude-vcs -cf - -C $LIBCXX include | tar -xf -

echo "SUCCESS"
