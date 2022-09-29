#!/bin/bash

(
  SLEEP=0
  for i in `seq 1 5`; do
    sleep $SLEEP
    SLEEP=$(( SLEEP + 10))

    (
      set -ex
      apt-get -qq -y update || exit 1
      apt-get install -qq -y gnupg || exit 1

      ARCH_PACKAGES=
      if [[ "$(arch)" == "x86_64" ]]; then
        dpkg --add-architecture i386
        ARCH_PACKAGES="g++-multilib gcc-multilib libc6-dev:i386"
      fi

      echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
      dpkg --configure -a
      apt-get -qq -y update || exit 1
      
      apt-get install -qq -y \
        ${ARCH_PACKAGES} \
        automake \
        bc \
        binutils-dev \
        binutils \
        bison \
        buildbot-worker \
        ccache \
        cmake \
        clang lld \
        curl \
        debootstrap \
        dos2unix \
        e2fsprogs \
        flex \
        g++ \
        gawk \
        git \
        inetutils-ping \
        jq \
        libattr1-dev \
        libc6-dev \
        libcap-ng-dev \
        libelf-dev \
        libfdt-dev \
        libgcrypt-dev \
        libglib2.0-dev \
        libgss-dev \
        liblzma-dev \
        libpixman-1-dev \
        libssl-dev \
        libstdc++*-dev-* \
        libtinfo-dev \
        libtinfo5 \
        libtool \
        libxml2-dev \
        mc \
        mdadm \
        m4 \
        make \
        nfs-kernel-server \
        ninja-build \
        openssh-client \
        pkg-config \
        python-is-python3 \
        python3-dev \
        python3-distutils \
        python3-psutil \
        psmisc \
        rsync \
        wget \
        xfsprogs \
        zlib1g-dev || exit 1
    ) && exit 0
  done
  exit 1
) || $ON_ERROR

# Optional, ingore if it fails.
curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh
bash add-google-cloud-ops-agent-repo.sh --also-install

update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.lld" 30
update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.gold" 20
update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.bfd" 10
