#!/bin/bash

(
  SLEEP=0
  for i in `seq 1 5`; do
    sleep $SLEEP
    SLEEP=$(( SLEEP + 10))
    APT_OPTS="-o DPkg::Lock::Timeout=300 -qq -y"

    (
      set -ex
      rm -f /etc/apt/sources.list.d/scalibr-apt.list # can't update
      apt ${APT_OPTS} update || true
      apt ${APT_OPTS} install gnupg || exit 1
      curl -f https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add - || exit 1

      ARCH_PACKAGES=
      if [[ "$(arch)" == "x86_64" ]]; then
        dpkg --add-architecture i386
        ARCH_PACKAGES="g++-multilib gcc-multilib libc6-dev:i386"
      fi

      echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
      dpkg --configure -a
      apt ${APT_OPTS} update || exit 1

      apt ${APT_OPTS} install gcc || exit 1

      apt ${APT_OPTS} install \
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
        libstdc++-$(gcc -dumpversion)-dev* \
        libtinfo-dev \
        libtinfo.$ \
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
        python3-psutil \
        python3-venv \
        psmisc \
        rsync \
        time \
        wget \
        xfsprogs \
        zlib1g-dev || exit 1
    ) && exit 0
  done
  exit 1
) || $ON_ERROR

update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.lld" 30
update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.gold" 20
update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.bfd" 10

apt ${APT_OPTS} clean
