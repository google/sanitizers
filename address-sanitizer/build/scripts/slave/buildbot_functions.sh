#!/bin/bash

function buildbot_update {
    REV_ARG=
    if [ "$BUILDBOT_REVISION" != "" ]; then
        REV_ARG="-r$BUILDBOT_REVISION"
    fi

    if [ -d llvm -a -d llvm/projects/libcxx ]; then
        svn up llvm $REV_ARG
        if [ "$REV_ARG" == "" ]; then
            REV_ARG="-r"$(svn info llvm | grep '^Revision:' | awk '{print $2}')
        fi
        svn up llvm/tools/clang $REV_ARG
        svn up llvm/projects/compiler-rt $REV_ARG
        svn up llvm/projects/libcxx $REV_ARG
    else
        svn co http://llvm.org/svn/llvm-project/llvm/trunk llvm $REV_ARG
        if [ "$REV_ARG" == "" ]; then
            REV_ARG="-r"$(svn info llvm | grep '^Revision:' | awk '{print $2}')
        fi
        svn co http://llvm.org/svn/llvm-project/cfe/trunk llvm/tools/clang $REV_ARG
        svn co http://llvm.org/svn/llvm-project/compiler-rt/trunk llvm/projects/compiler-rt $REV_ARG
        svn co http://llvm.org/svn/llvm-project/libcxx/trunk llvm/projects/libcxx $REV_ARG
    fi
}
