#!/bin/bash

set -eux

rm -rf gcc*

curl -o gcc-4.9.2.tar.bz2 http://mirrors-ru.go-parts.com/gcc/releases/gcc-4.9.2/gcc-4.9.2.tar.bz2 
tar -xf gcc-4.9.2.tar.bz2

mkdir -p gcc_build
cd gcc_build
../gcc-4.9.2/configure --disable-multilib --disable-bootstrap --enable-languages=c,c++ --prefix=${PWD}/../gcc_install

make -j64
make install


