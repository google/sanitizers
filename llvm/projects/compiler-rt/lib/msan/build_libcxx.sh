#!/bin/bash

LIBCXX=$(cd ../../../libcxx; pwd)
CLANG_BUILD=$(cd ../../../../build; pwd)
CXX=$CLANG_BUILD/bin/clang++
CC=$CLANG_BUILD/bin/clang
#echo $LIBCXX
#echo $CLANG_BUILD

rm -rf libcxx && mkdir -p libcxx/lib
cd libcxx

make_include() {
  cp -rf $LIBCXX/include .
  cd include
  ln -s $(find . /usr/include/ -name cxxabi.h) .
  ln -s $(find . /usr/include/ -name cxxabi-forced.h) .
  mkdir bits && cd bits
  ln -s $(find /usr/include/ -name cxxabi_tweaks.h | grep -v /32/) .
}

make_lib() {
  cd lib
  CXXFLAGS="-fmemory-sanitizer -I$LIBCXX/include -fPIE -fPIC -w -c -g -Os -std=c++0x -fstrict-aliasing -nostdinc++"

  for f in $LIBCXX/src/*.cpp; do $CXX $CXXFLAGS $f & done; wait

  $CC *.o -fPIC -o libc++.so.1.0 -shared -nodefaultlibs -Wl,-soname,libc++.so.1 -lpthread -lrt -lc -lstdc++ -std=c++0x
  rm -f *.o

  ln -s libc++.so.1.0 libc++.so.1
  ln -s libc++.so.1.0 libc++.so

  libsupcxx=$(find /usr/lib/gcc -name 'libsupc++.a' |grep -v /32/)
  cp $libsupcxx .
  ar x libsupc++.a
  rm libsupc++.a
  rm del_op*.o new_op*.o
  ar ru msansup.a *.o
}

(make_lib)
(make_include)
