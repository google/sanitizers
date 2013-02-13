#!/bin/bash

ARG=$1
shift

if [ "z$ARG" == "z--msan" ]; then
  FLAGS="-fsanitize=memory -fsanitize-memory-track-origins -pie"
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

if [ "z$LIBCXX" == "z" ]; then
  echo "Please set \$LIBCXX to the location of msan-enabled libcxx/libcxxabi library."
  exit 1
fi

HERE=$(cd $(dirname $0) && pwd)

cat $HERE/clang.tmpl | perl -pe "s#\\@LLVM_BIN\\@#$LLVM_BIN#g" >_clang
cat $HERE/clang.tmpl | perl -pe "s#\\@LLVM_BIN\\@#$LLVM_BIN#g" >_clang++
chmod +x _clang _clang++

CLANG=`pwd`/_clang
CLANGXX=`pwd`/_clang++
LIBCXX_INCLUDE=$LLVM/projects/libcxx
LIBCXXABI=$LLVM/projects/libcxxabi

# FLAGS="-fPIC -fno-omit-frame-pointer -w -O1 -g -fno-inline-functions -fno-inline -stdlib=libc++ -I$LIBCXX/include \
# -I$LIBCXXABI/include \
# -L$LIBCXX/lib -Wl,-R$LIBCXX/lib -L$LIBCXXABI/lib -Wl,-R$LIBCXXABI/lib -lc++abi \
# $FLAGS"


FLAGS="-fPIC -w -g -fno-omit-frame-pointer -stdlib=libc++ \
-I$LLVM/projects/libcxx/include \
-I$LLVM/projects/libcxxabi/includ \
-L$LIBCXX -Wl,-R$LIBCXX -lc++abi \
$FLAGS"

set -x
CC="$CLANG" \
CXX="$CLANGXX" \
cmake -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_ENABLE_ASSERTIONS=ON \
    -DCMAKE_C_FLAGS="$FLAGS" \
    -DCMAKE_CXX_FLAGS="$FLAGS" \
    $LLVM
