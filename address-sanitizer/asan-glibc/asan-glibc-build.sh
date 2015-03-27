#!/bin/bash
HERE=$(pwd)
J=32
GLIBC=$HERE/glibc-2.19
PLAIN_BUILD=$HERE/plain-build
ASAN_BUILD=$HERE/asan-build
ASAN_INST=$HERE/asan-inst
PATH=$HOME/toolchains/gcc-trunk/bin:$PATH

set -xe

get_glibc() {
 wget http://ftp.gnu.org/gnu/glibc/glibc-$1.tar.bz2
 tar xf glibc-$1.tar.bz2
}

build_plain() {
  rm -rf $PLAIN_BUILD
  mkdir $PLAIN_BUILD
  cd $PLAIN_BUILD
  $GLIBC/configure --prefix=$ASAN_INST && make -j $J && make install
  cd $HERE
}

build_asan() {
  # Temporary, see comment in asan-init-stub.c
  gcc -c asan-init-stub.c -o asan-init-stub.o -fPIC
  rm -rf $ASAN_BUILD
  mkdir $ASAN_BUILD
  cd $ASAN_BUILD
  CC=$HERE/asan-glibc-gcc-wrapper.py $GLIBC/configure --prefix=/usr/ && \
    make -j $J  -C $GLIBC objdir=`pwd` lib > mk
  cp -v libc.so $ASAN_INST/lib/libc-*.so
  cd $HERE
}

test_asan() {
  clang -c asan-glibc-test.c
  clang asan-glibc-test.o  \
    -Wl,-rpath=${ASAN_INST}/lib \
    -fsanitize=address -o asan_glibc_test
   export ASAN_OPTIONS=detect_odr_violation=0
   ./asan_glibc_test           2>&1 | grep strsep || echo FAIL
   ./asan_glibc_test  1        2>&1 | grep strverscmp  || echo FAIL
   ./asan_glibc_test  1 2      2>&1 | grep getenv || echo FAIL
   ./asan_glibc_test  1 2 3    2>&1 | grep nss_hostname_digits_dots || echo FAIL
   ./asan_glibc_test  1 2 3 4  2>&1 | grep internal_fnmatch || echo FAIL

}

 get_glibc 2.19
 build_plain
 build_asan
 test_asan
