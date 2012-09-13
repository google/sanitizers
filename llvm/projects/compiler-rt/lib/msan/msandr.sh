#!/bin/bash

ulimit -s 8192
MSANDR_PATH=../../../../../msandr
ls -l $MSANDR_PATH
DRRUN=$MSANDR_PATH/dr/build/bin64/drrun
MSANDR=$MSANDR_PATH/build/libmsandr.so
export LD_USE_LOAD_BIAS=1
#echo ================= "$@" =================
$DRRUN -client $MSANDR 0 "" -- "$@"
