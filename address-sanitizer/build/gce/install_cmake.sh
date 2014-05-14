#!/bin/bash
mkdir -p $HOME/bin && \
  curl http://www.cmake.org/files/v2.8/cmake-2.8.12.2.tar.gz | tar zx && \
  cd cmake-2.8.12.2 && \
  ./bootstrap && \
  make -j 4 &&
  cp -v bin/cmake $HOME/bin

