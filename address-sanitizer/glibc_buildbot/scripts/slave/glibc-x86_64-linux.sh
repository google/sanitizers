#!/bin/bash

set -x
set -e
set -u

echo @@@BUILD_STEP sync@@@

root_dir=$(pwd)
src_dir="${root_dir}/glibc"
build_dir="${root_dir}/build"

if [ -d ${src_dir} ]; then
  cd ${src_dir}
  git pull
  cd ${root_dir}
else
  git clone git://sourceware.org/git/glibc.git ${src_dir}
fi


echo @@@BUILD_STEP configure@@@

mkdir -p $build_dir
cd $build_dir
${src_dir}/configure --prefix=/usr --enable-add-ons

num_jobs=$(getconf _NPROCESSORS_ONLN)


echo @@@BUILD_STEP make@@@

make -j${num_jobs} -k

echo @@@BUILD_STEP check@@@

make -j${num_jobs} -k check
