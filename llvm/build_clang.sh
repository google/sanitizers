#!/bin/bash

rm -rf clang_build
mkdir -p clang_build
cd clang_build
../clang_src/configure
make -j ${J:-16} ENABLE_OPTIMIZED=1

