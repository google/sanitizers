#!/bin/bash

rm -rf $BOT_DIR
mkdir -p $BOT_DIR

cat <<EOF >/etc/apt/preferences.d/99hirsute
Package: *
Pin: release a=hirsute
Pin-Priority: 1

Package: *-cross
Pin: release a=hirsute
Pin-Priority: 600
EOF


(
  SLEEP=0
  for i in `seq 1 5`; do
    sleep $SLEEP
    SLEEP=$(( SLEEP + 10))

    (
      set -ex
      apt-get -qq -y update || exit 1
      apt-get install -qq -y gnupg || exit 1

      apt-key adv --recv-keys --keyserver keyserver.ubuntu.com FEEA9169307EA071 || exit 1
      apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 871920D1991BC93C || exit 1

      dpkg --add-architecture i386
      echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
      dpkg --configure -a
      apt-get -qq -y update || exit 1
      
      # Install MTE compartible glibc 2.33 from Ubuntu.
      apt-get -qq -y install software-properties-common || exit 1
      add-apt-repository -y 'deb http://mirrors.kernel.org/ubuntu hirsute main' || exit 1
      apt-get -qq -y update || exit 1

      apt-get install -qq -y \
        automake \
        bc \
        binutils-dev \
        binutils \
        bison \
        buildbot-worker \
        ccache \
        cmake \
        debootstrap \
        dos2unix \
        e2fsprogs \
        flex \
        g++ \
        g++-multilib \
        gawk \
        gcc-multilib \
        git \
        jq \
        libelf-dev \
        libfdt-dev \
        libgcrypt-dev \
        libglib2.0-dev \
        libgss-dev \
        liblzma-dev \
        libpixman-1-dev \
        libssl-dev \
        libstdc++*-dev-*-cross \
        libtinfo-dev \
        libtinfo5 \
        libtool \
        libxml2-dev \
        m4 \
        make \
        ninja-build \
        openssh-client \
        pkg-config \
        python-dev \
        python3-distutils \
        python3-psutil \
        rsync \
        wget \
        zlib1g-dev || exit 1
    ) && exit 0
  done
  exit 1
) || $ON_ERROR

# Optional, ingore if it fails.
curl -sSO https://dl.google.com/cloudagents/add-monitoring-agent-repo.sh
bash add-monitoring-agent-repo.sh --also-install --remove-repo
sudo service stackdriver-agent start

update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.gold" 20
update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.bfd" 10

# Make sure /var/lib/buildbot/.cache/clang/ModuleCache/ does not grow over time.
rm -rf /var/lib/buildbot/.cache/clang

mkdir -p /var/lib/buildbot/.ccache
chown -R buildbot:buildbot /var/lib/buildbot/.ccache
cat <<EOF >/var/lib/buildbot/.ccache/ccache.conf
max_size = 50.0G
compression = true
EOF
