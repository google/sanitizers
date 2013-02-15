#!/bin/bash

ARG=$1
shift

WITH_LIBCXX=

if [ "z$ARG" == "z--msan-origins" ]; then
  FLAGS="-fsanitize=memory -fsanitize-memory-track-origins -pie"
  WITH_LIBCXX=1
  ARG=$1
  shift
elif [ "z$ARG" == "z--msan" ]; then
  FLAGS="-fsanitize=memory -pie"
  WITH_LIBCXX=1
  ARG=$1
  shift
elif [ "z$ARG" == "z--asan" ]; then
  FLAGS="-fsanitize=address -pie"
  ARG=$1
  shift
fi

if [ "z$ARG" == "z" ]; then
  echo "Usage: $0 [--msan] llvmsrcpath"
  exit 1
fi

LLVM=$ARG

if [ "z$LLVM_BIN" == "z" ]; then
  echo "Please set \$LLVM_BIN to the location of sanitizer-enabled 'clang' binary."
  exit 1
fi

if [ "z$WITH_LIBCXX" != "z" ]; then
    if [ "z$LIBCXX" == "z" ]; then
        echo "Please set \$LIBCXX to the location of msan-enabled libcxx/libcxxabi library."
        exit 1
    fi
fi

HERE=$(cd $(dirname $0) && pwd)

cat $HERE/clang.tmpl | perl -pe "s#\\@LLVM_BIN\\@#$LLVM_BIN#g" >_clang
cat $HERE/clang.tmpl | perl -pe "s#\\@LLVM_BIN\\@#$LLVM_BIN#g" >_clang++
chmod +x _clang _clang++

CLANG=`pwd`/_clang
CLANGXX=`pwd`/_clang++
FLAGS="-fPIC -w -g -fno-omit-frame-pointer $FLAGS"

if [ "z$WITH_LIBCXX" != "z" ]; then
    FLAGS="-stdlib=libc++ \
-I$LLVM/projects/libcxx/include \
-I$LLVM/projects/libcxxabi/include \
-L$LIBCXX -Wl,-R$LIBCXX -lc++abi \
$FLAGS"
fi

set -x
CC="$CLANG" \
CXX="$CLANGXX" \
cmake -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_ENABLE_ASSERTIONS=ON \
    -DCMAKE_C_FLAGS="$FLAGS" \
    -DCMAKE_CXX_FLAGS="$FLAGS" \
    $LLVM
