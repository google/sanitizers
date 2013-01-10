#!/bin/bash

ulimit -s 8192

HERE=$(dirname $0)
MSANDR_PATH=$HERE/../../../../../msandr
DRRUN=$MSANDR_PATH/drmemory/build/dynamorio/bin64/drrun
MSANDR=$MSANDR_PATH/build/libmsandr.so
export LD_USE_LOAD_BIAS=1
#echo ================= "$@" =================
$DRRUN -v -debug -checklevel 1 -persist -persist_dir /tmp/pcache -c $MSANDR -- "$@"
#$DRRUN -v -debug -c $MSANDR -- "$@"
