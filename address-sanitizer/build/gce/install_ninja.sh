#!/bin/bash
echo Installing ninja
mkdir -p bin
git clone git://github.com/martine/ninja.git && \
  cd ninja  && \
  ./bootstrap.py && \
  cp -v ninja $HOME/bin


