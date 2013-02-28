#!/bin/bash

# Simple script to run CPU2006 with AddressSanitizer.
# Make sure to use spec version 1.2 (SPEC_CPU2006v1.2).
# Run this script like this:
# $./run_spec_clang_asan.sh TAG [test|train|ref] benchmarks
# TAG is any word. If you use different TAGS you can runs several builds in
# parallel.
# test is a small data set, train is medium, ref is large.
# To run all C use all_c, for C++ use all_cpp

name=$1
shift
size=$1
shift

ulimit -s 8092  # stack

SPEC_J=${SPEC_J:-20}
NUM_RUNS=${NUM_RUNS:-1}
F_ASAN=-fsanitize=address
CLANG=${CLANG:-clang}
BIT=${BIT:-64}
OPT_LEVEL=${OPT_LEVEL:-"-O2"}

# Ignore file for known  bugs in spec.
cat <<EOF > asan_spec.ignore
fun:Perl_sv_setpvn
fun:SATD
fun:biari_init_context
EOF

rm -rf config/$name.*

COMMON_FLAGS="$F_ASAN -m$BIT "
CC="$CLANG     -std=gnu89 $COMMON_FLAGS"
CXX="${CLANG}++           $COMMON_FLAGS"

cat << EOF > config/$name.cfg
monitor_wrapper = $SPEC_WRAPPER  \$command
ignore_errors = yes
tune          = base
ext           = $name
output_format = asc, Screen
reportable    = 1
teeout        = yes
teerunout     = yes
strict_rundir_verify = 0
makeflags = -j$SPEC_J

default=default=default=default:
CC  = $CC
CXX = $CXX
EXTRA_LIBS = $EXTRA_LIBS
FC         = echo

default=base=default=default:
COPTIMIZE     = $OPT_LEVEL
CXXOPTIMIZE  =  $OPT_LEVEL

default=base=default=default:
PORTABILITY = -DSPEC_CPU_LP64

400.perlbench=default=default=default:
CPORTABILITY= -DSPEC_CPU_LINUX_X64

462.libquantum=default=default=default:
CPORTABILITY= -DSPEC_CPU_LINUX

483.xalancbmk=default=default=default:
CXXPORTABILITY= -DSPEC_CPU_LINUX -include string.h

447.dealII=default=default=default:
CXXPORTABILITY= -include string.h -include stdlib.h -include cstddef
EOF

. shrc
runspec -c $name -a run -I -l --size $size -n $NUM_RUNS $@
