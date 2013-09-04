#!/bin/bash

DIR=$(dirname $0)
$DIR/bin64/drrun -disable_traces -c $DIR/libdr_asan.so $@
