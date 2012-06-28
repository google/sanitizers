#!/bin/bash

PIN_DIR=$HOME/pin_msan
PIN=$PIN_DIR/pin
MSAN_SO=$PIN_DIR/source/tools/SimpleExamples/obj-intel64/msan_pin.so

run() {
  # echo "$@"
  "$@"
}

run $PIN -t $MSAN_SO $PIN_FLAGS -- "$@"
