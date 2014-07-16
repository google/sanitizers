#!/bin/bash
MODE=$1
ID=$2
SIZE=${3:-ref}

VALGRIND=$HOME/valgrind-inst/bin/valgrind
CLANG=$HOME/build/llvm/build/bin/clang
EXTRA_CFLAGS=
WRAPPER=

if [[ $MODE == clang ]]; then
    EXTRA_CFLAGS=
elif [[ $MODE == msan ]]; then
    EXTRA_CFLAGS="-fsanitize=memory -Wl,-rpath,$HOME/libstdc++-msan"
elif [[ $MODE == msan-origins ]]; then
    EXTRA_CFLAGS="-fsanitize=memory -fsanitize-memory-track-origins \
-Wl,-rpath,$HOME/libstdc++-msan"
elif [[ $MODE == msan-origins2 ]]; then
    EXTRA_CFLAGS="-fsanitize=memory -fsanitize-memory-track-origins=2 \
-Wl,-rpath,$HOME/libstdc++-msan"
elif [[ $MODE == valgrind ]]; then
    SPEC_WRAPPER="$VALGRIND -q"
elif [[ $MODE == valgrind-origins ]]; then
    SPEC_WRAPPER="$VALGRIND -q --track-origins=yes"
else
    echo "bad mode"
    exit 1
fi

SPEC_WRAPPER="/usr/bin/time -f '%e %M %C' -o `pwd`/$ID.timelog -a $SPEC_WRAPPER"
if [[ z$TASKSET != z ]]; then
    SPEC_WRAPPER="taskset $TASKSET $SPEC_WRAPPER"
fi

if [[ -f `pwd`/$ID.timelog || -f $ID.log ]]; then
    echo "log files already exist"
    exit 1
fi

echo "CLANG=\"$CLANG\""
echo "EXTRA_CFLAGS=\"$EXTRA_CFLAGS\""
echo "SPEC_WRAPPER=\"$SPEC_WRAPPER\""
echo "SIZE=\"$SIZE\""

export CLANG
export EXTRA_CFLAGS
export SPEC_WRAPPER
./run_spec_clang.sh $ID $SIZE all_c all_cpp >& $ID.log &
