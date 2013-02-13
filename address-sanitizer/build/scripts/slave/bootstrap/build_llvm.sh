#!/bin/bash

ARG=$1
shift

if [ "z$ARG" == "z--msan" ]; then
  FLAGS="-fsanitize=memory -fsanitize-memory-track-origins -pie"
elif [ "z$ARG" != "z" ]; then
  echo "Unrecognized argument: $ARG"
  exit 1
fi

if [ "z$LLVM" == "z" ]; then
  echo "Please set \$LLVM to the LLVM source root path."
  exit 1
fi

if [ "z$LLVM_BIN" == "z" ]; then
  echo "Please set \$LLVM_BIN to the location of msan-enabled 'clang' binary."
  exit 1
fi

if ! [ -e $LLVM/LLVMBuild.txt ]; then
  echo "Please run me from LLVM/build directory."
  exit 1
fi

if ! [ -e $LLVM/projects/libcxx/lib/libc++.so ]; then
  echo "Please run build_libcxx.sh first."
  exit 1
fi

if ! [ -e $LLVM/projects/libcxxabi/lib/libc++abi.so ]; then
  echo "Please run build_libcxxabi.sh first."
  exit 1
fi

HERE=$(cd $(dirname $0) && pwd)

cat $HERE/clang.tmpl | perl -pe "s#\\@LLVM_BIN\\@#$LLVM_BIN#g" >_clang
cat $HERE/clang.tmpl | perl -pe "s#\\@LLVM_BIN\\@#$LLVM_BIN#g" >_clang++
chmod +x _clang _clang++

CLANG=`pwd`/_clang
CLANGXX=`pwd`/_clang++
LIBCXX=$LLVM/projects/libcxx
LIBCXXABI=$LLVM/projects/libcxxabi

# FLAGS="-fPIC -fno-omit-frame-pointer -w -O1 -g -fno-inline-functions -fno-inline -stdlib=libc++ -I$LIBCXX/include \
# -I$LIBCXXABI/include \
# -L$LIBCXX/lib -Wl,-R$LIBCXX/lib -L$LIBCXXABI/lib -Wl,-R$LIBCXXABI/lib -lc++abi \
# $FLAGS"


FLAGS="-fPIC -w -g -fno-omit-frame-pointer -stdlib=libc++ -I$LIBCXX/include \
-I$LIBCXXABI/include \
-L$LIBCXX/lib -Wl,-R$LIBCXX/lib -L$LIBCXXABI/lib -Wl,-R$LIBCXXABI/lib -lc++abi \
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

