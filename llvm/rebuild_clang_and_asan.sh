#!/bin/bash
(cd clang_build/lib/Transforms/Instrumentation/ && make -j16 ENABLE_OPTIMIZED=1) && \
(cd clang_build/tools/clang/ && make -j16 ENABLE_OPTIMIZED=1)
