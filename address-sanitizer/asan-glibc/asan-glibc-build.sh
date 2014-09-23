#!/bin/bash
HERE=$(pwd)
J=32
GLIBC=$HERE/glibc-2.19
PLAIN_BUILD=$HERE/plain-build
ASAN_BUILD=$HERE/asan-build
ASAN_INST=$HERE/asan-inst

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
  rm -rf $ASAN_BUILD
  mkdir $ASAN_BUILD
  cd $ASAN_BUILD
  CC=$HERE/asan-glibc-gcc-wrapper.py $GLIBC/configure --prefix=$ASAN_INST && \
    make -j $J  -C $GLIBC objdir=`pwd` lib > mk
  cp -v libc.so $ASAN_INST/lib/libc-*.so
  cd $HERE
}

test_asan() {
  LD_SO=$(echo ${ASAN_INST}/lib/ld-2.*.so)
  echo $LD_SO
  clang -c asan-glibc-test.c
  clang asan-glibc-test.o  \
    -Wl,-rpath=${ASAN_INST}/lib  -Wl,-dynamic-linker=$LD_SO \
    -fsanitize=address -o asan_glibc_test
   export ASAN_OPTIONS=detect_odr_violation=0
   ./asan_glibc_test           2>&1 | grep strsep
   ./asan_glibc_test  1        2>&1 | grep strverscmp
   ./asan_glibc_test  1 2      2>&1 | grep getenv
   ./asan_glibc_test  1 2 3    2>&1 | grep nss_hostname_digits_dots
   ./asan_glibc_test  1 2 3 4  2>&1 | grep internal_fnmatch
}

 get_glibc 2.19
 build_plain
 build_asan
 test_asan
