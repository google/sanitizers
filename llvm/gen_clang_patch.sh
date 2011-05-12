#!/bin/bash
(cd clang_src && svn diff && svn diff tools/clang)  > llvm/clang.patch
