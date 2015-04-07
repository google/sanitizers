#!/bin/bash

set -x
set -u

configure_args=(
  --prefix=/usr
  --enable-add-ons
  "$@"
)

nproc=$(getconf _NPROCESSORS_ONLN)

root_dir=$(pwd)
src_dir="${root_dir}/glibc"
build_dir="${root_dir}/build"

num_jobs_build=$nproc
# Some make bug makes it often wedge in parallel mode.
num_jobs_check=1

clobber=false

start_step() {
  local say_clobber=
  if $clobber; then
    say_clobber=' (clobber)'
  fi
  echo "@@@BUILD_STEP $*${say_clobber}@@@"
}

end_step() {
  local rc=$?
  if [ $rc -ne 0 ]; then
    echo '@@@STEP_FAILURE@@@'
  fi
  return $rc
}

do_sync() {
  start_step sync
  if [ -d "${src_dir}" ]; then
    (cd "${src_dir}" && git remote prune origin && git pull)
  else
    git clone git://sourceware.org/git/glibc.git ${src_dir}
  fi
  end_step
}

do_configure() {
  start_step configure
  mkdir -p "$build_dir"
  (cd "$build_dir" && "${src_dir}"/configure "${configure_args[@]}")
  end_step
}

do_build() {
  start_step make
  make -C "${build_dir}" -j${num_jobs_build} -k
  end_step
}

do_check() {
  start_step check
  make -C "${build_dir}" -j${num_jobs_check} -k check
  end_step
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

do_whole_build
rc=$?

if [ $rc -ne 0 ] && $need_clobber; then
  do_clobber && do_whole_build
  rc=$?
fi

exit $rc
