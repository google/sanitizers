#!/bin/bash

function buildbot_update {
    REV_ARG=
    if [ "$BUILDBOT_REVISION" != "" ]; then
        REV_ARG="-r$BUILDBOT_REVISION"
    fi
    if [ -d llvm ]; then
        svn cleanup llvm
    fi
    for subtree in llvm/tools/clang llvm/projects/compiler-rt llvm/projects/libcxx llvm/projects/libcxxabi
    do
      if [ -d ${subtree} ]; then
        svn cleanup "${subtree}"
      fi
    done

    if [ -d llvm -a -d llvm/projects/libcxxabi ]; then
        svn up llvm $REV_ARG
        if [ "$REV_ARG" == "" ]; then
            REV_ARG="-r"$(svn info llvm | grep '^Revision:' | awk '{print $2}')
        fi
        for subtree in llvm/tools/clang llvm/projects/compiler-rt llvm/projects/libcxx llvm/projects/libcxxabi
        do
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

function fetch_depot_tools {
  ROOT=$1
  (
    cd $ROOT
    if [ ! -d depot_tools ]; then
      git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
    fi
  )
  export PATH="$ROOT/depot_tools:$PATH"
}

function check_out_chromium {
  CHROME_CHECKOUT=$1
  (
  if [ ! -d $CHROME_CHECKOUT ]; then
    mkdir $CHROME_CHECKOUT
    pushd $CHROME_CHECKOUT
    fetch --nohooks chromium --nosvn=True 

    # Sync to LKGR, see http://crbug.com/109191
    mv .gclient .gclient-tmp
    cat .gclient-tmp  | \
        sed 's/"safesync_url": ""/"safesync_url": "https:\/\/chromium-status.appspot.com\/git-lkgr"/' > .gclient
    rm .gclient-tmp
    popd
  fi
  cd $CHROME_CHECKOUT/src
  git checkout master
  git pull
  gclient sync --nohooks --jobs=16
  )
}

function gclient_runhooks {
  CHROME_CHECKOUT=$1
  CLANG_BUILD=$2
  CUSTOM_GYP_DEFINES=$3
  (
  cd $CHROME_CHECKOUT/src
  
  # Clobber Chromium to catch possible LLVM regressions early.
  rm -rf out/Release
  
  export COMMON_GYP_DEFINES="use_allocator=none use_aura=1 clang_use_chrome_plugins=0 component=static_library"
  export GYP_DEFINES="$CUSTOM_GYP_DEFINES $COMMON_GYP_DEFINES"
  export GYP_GENERATORS=ninja
  export CLANG_BIN=$CLANG_BUILD/bin
  export CC="$CLANG_BIN/clang"
  export CXX="$CLANG_BIN/clang++"
  
  gclient runhooks
  )
}
