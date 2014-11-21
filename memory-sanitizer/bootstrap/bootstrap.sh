#!/bin/bash

HERE=$PWD

[ -x "$CLANG" ] || echo "\$CLANG unset or missing or non-executable"; exit 1

# Build libc++ and libc++abi with MSan.
mkdir build-msan-libs && cd build-msan-libs
CC=$CLANG CXX=$CLANG++ cmake \
    -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_ENABLE_ASSERTIONS=ON \
    -DLLVM_ENABLE_WERROR=ON \
    -DLLVM_USE_SANITIZER=MemoryWithOrigins \
    ..
ninja cxx cxxabi
cd ..

mkdir build-msan && cd build-msan
MSAN_CFLAGS="-I$HERE/build-msan-libs/include"
MSAN_CXXFLAGS="$MSAN_CFLAGS -stdlib=libc++"
MSAN_LDFLAGS="-stdlib=libc++ -lc++abi -L$HERE/build-msan-libs/lib -Wl,-rpath,$HERE/build-msan-libs/lib"
CC=$CLANG CXX=$CLANG++ cmake \
    -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_ENABLE_ASSERTIONS=ON \
    -DLLVM_ENABLE_WERROR=ON \
    -DLLVM_USE_SANITIZER=MemoryWithOrigins \
    -DCMAKE_C_FLAGS="$MSAN_CFLAGS" \
    -DCMAKE_CXX_FLAGS="$MSAN_CXXFLAGS" \
    -DCMAKE_EXE_LINKER_FLAGS="$MSAN_LDFLAGS" \
    ..
ninja
