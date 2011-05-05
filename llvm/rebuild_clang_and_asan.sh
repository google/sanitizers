#!/bin/bash
(cd clang_build/lib/Transforms/Instrumentation/ && make -j16) && \
(cd clang_build/tools/clang/ && make -j16)
