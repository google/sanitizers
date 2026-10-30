#!/bin/bash

(
  SLEEP=0
  for i in `seq 1 5`; do
    sleep $SLEEP
    SLEEP=$(( SLEEP + 10))
    APT_OPTS="-o DPkg::Lock::Timeout=300 -qq -y"

    (
      set -ex
      rm -f /etc/apt/sources.list.d/scalibr-apt.list /etc/apt/sources.list.d/google-cloud-ops-agent.list # can't update
      apt ${APT_OPTS} update || true
      apt ${APT_OPTS} install ca-certificates curl gnupg || exit 1
      # curl -f https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add - || exit 1

      ARCH_PACKAGES=
      if [[ "$(arch)" == "x86_64" ]]; then
        curl -fsSL https://us-apt.pkg.dev/doc/repo-signing-key.gpg \
          -o /etc/apt/trusted.gpg.d/artifact-registry.asc || exit 1
        echo "deb https://us-apt.pkg.dev/projects/android-cuttlefish-artifacts android-cuttlefish main" \
          >/etc/apt/sources.list.d/artifact-registry.list

        dpkg --add-architecture i386
        # libasound2t64 and libpulse0 are dynamically linked by Cuttlefish's
        # prebuilt qemu-system-aarch64.
        ARCH_PACKAGES="adb g++-multilib gcc-multilib libasound2t64 libc6-dev:i386 libpulse0"
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
        bzip2 \
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
        unzip \
        wget \
        xfsprogs \
        zlib1g-dev || exit 1

      if [[ "$(arch)" == "x86_64" ]]; then
        # Fall back to 1.56.0 while 1.57.0 depends on libxml2 (removed in Ubuntu 26.04+).
        apt ${APT_OPTS} install cuttlefish-base cuttlefish-user || \
          apt ${APT_OPTS} install cuttlefish-base=1.56.0 cuttlefish-user=1.56.0 || exit 1
      fi
    ) && exit 0
  done
  exit 1
) || exit 1

update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.lld" 30
update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.gold" 20
update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.bfd" 10

# Work around for https://sourceware.org/git/?p=glibc.git;a=commit;h=243bdfec8f7cd4a85a8ce6e4e9a5a5accd3ce1aa
find / -type f -name "struct_mutex.h" -exec sed -i 's/short __unused;/short __glibc_unused;/' {} +

apt ${APT_OPTS} clean
