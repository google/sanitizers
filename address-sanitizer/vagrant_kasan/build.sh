#!/bin/bash
set -o pipefail
set -eux

function get_gcc() {
  svn checkout -r 212893 svn://gcc.gnu.org/svn/gcc/trunk gcc_kasan

  cd gcc_kasan
  patch -p0 -i /vagrant/gcc-r212893-kasan-stack.patch
}

function make_gcc() {
  mkdir gcc_build
  cd gcc_build

  ../gcc_kasan/configure --disable-multilib --disable-bootstrap --enable-languages=c,c++ --prefix=/home/vagrant/gcc_install/

  make -j8
  make install
}

function get_kasan() {
  git clone https://github.com/google/kasan.git
}

function make_kasan() {
  cd kasan

  cp /vagrant/kernel_config .config
  make oldconfig

  make -j8 deb-pkg LOCALVERSION=-asan CC=~/gcc_install/bin/gcc
}

function main() {
  case "$1" in
    get_gcc|make_gcc|get_kasan|make_kasan)
      ${1}
      ;;
    *)
      echo "Usage: $0 {get_gcc|make_gcc|get_kasan|make_kasan}"
      exit 1
esac
}

main $@ ""
