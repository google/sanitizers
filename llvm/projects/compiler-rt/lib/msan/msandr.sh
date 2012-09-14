#!/bin/bash

ulimit -s 8192

HERE=$(dirname $0)
MSANDR_PATH=$HERE/../../../../../msandr
DRRUN=$MSANDR_PATH/dr/build/bin64/drrun
MSANDR=$MSANDR_PATH/build/libmsandr.so
export LD_USE_LOAD_BIAS=1
#echo ================= "$@" =================
$DRRUN -client $MSANDR 0 "" -- "$@"
