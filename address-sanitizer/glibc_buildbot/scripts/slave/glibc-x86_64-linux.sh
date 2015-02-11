#!/bin/bash

set -x
set -e
set -u


nproc=$(getconf _NPROCESSORS_ONLN)

root_dir=$(pwd)
src_dir="${root_dir}/glibc"
build_dir="${root_dir}/build"

num_jobs_build=$nproc
# Some make bug makes it often wedge in parallel mode.
num_jobs_check=1

clobber=false
annotate_clobber=''

annotate_step() {
  local say_clobber=
  if $clobber; then
    say_clobber=' (clobber)'
  fi
  echo "@@@BUILD_STEP $*${say_clobber}@@@"
}

do_sync() {
  annotate_step sync
  if [ -d "${src_dir}" ]; then
    (cd "${src_dir}"; git pull)
  else
    git clone git://sourceware.org/git/glibc.git ${src_dir}
  fi
}

do_configure() {
  annotate_step configure
  mkdir -p "$build_dir"
  (cd "$build_dir" &&
   "${src_dir}"/configure --prefix=/usr --enable-add-ons
  )
}

do_build() {
  annotate_step make
  make -C "${build_dir}" -j${num_jobs_build} -k
}

do_check() {
  annotate_step check
  make -C "${build_dir}" -j${num_jobs_check} -k check
}

do_clobber() {
  clobber=true
  cd "$root_dir"
  rm -rf "$build_dir"
}


do_whole_build() {
  do_configure &&
  do_build &&
  do_check
}

###

do_sync

if [ -d "${build_dir}" ]; then
  need_clobber=true
else
  need_clobber=false
fi

do_whole_build || {
  $need_clobber && do_clobber && do_whole_build
}
