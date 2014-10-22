#!/bin/bash

set -eux

rm -rf gcc_src gcc_build gcc_install
svn checkout -r 216458 svn://gcc.gnu.org/svn/gcc/trunk gcc_src
cd gcc_src
patch -p0 < ../gcc-216546.patch
cd ../

mkdir -p gcc_build
cd gcc_build
../gcc_src/configure --disable-multilib --disable-bootstrap --enable-languages=c,c++ --prefix=${PWD}/../gcc_install

make -j64
make install


