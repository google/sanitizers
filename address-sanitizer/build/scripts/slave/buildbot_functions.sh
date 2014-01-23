#!/bin/bash

function buildbot_update {
    REV_ARG=
    if [ "$BUILDBOT_REVISION" != "" ]; then
        REV_ARG="-r$BUILDBOT_REVISION"
    fi

    if [ -d llvm -a -d llvm/projects/libcxxabi ]; then
        svn cleanup llvm
        svn up llvm $REV_ARG
        if [ "$REV_ARG" == "" ]; then
            REV_ARG="-r"$(svn info llvm | grep '^Revision:' | awk '{print $2}')
        fi
        for subtree in llvm/tools/clang llvm/projects/compiler-rt llvm/projects/libcxx llvm/projects/libcxxabi
        do
          svn cleanup "${subtree}"
          svn up "${subtree}" $REV_ARG
        done
    else
        svn co http://llvm.org/svn/llvm-project/llvm/trunk llvm $REV_ARG
        if [ "$REV_ARG" == "" ]; then
            REV_ARG="-r"$(svn info llvm | grep '^Revision:' | awk '{print $2}')
        fi
        svn co http://llvm.org/svn/llvm-project/cfe/trunk llvm/tools/clang $REV_ARG
        svn co http://llvm.org/svn/llvm-project/compiler-rt/trunk llvm/projects/compiler-rt $REV_ARG
        svn co http://llvm.org/svn/llvm-project/libcxx/trunk llvm/projects/libcxx $REV_ARG
        svn co http://llvm.org/svn/llvm-project/libcxxabi/trunk llvm/projects/libcxxabi $REV_ARG
    fi
}

function set_chrome_suid_sandbox {
  export CHROME_DEVEL_SANDBOX=/usr/local/sbin/chrome-devel-sandbox
}

