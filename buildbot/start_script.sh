#!/bin/bash

BOT_DIR=/b
BOT_NAME=$1
BOT_PASS=$2

apt-get update -y
apt-get upgrade -y
apt-get install -y \
 buildbot-slave \
 subversion \
 g++ \
 cmake \
 binutils-gold \
 binutils-dev \
 ninja-build \
 pkg-config \
 gcc-multilib \
 gawk
 
if [[ "$BOT_NAME" == "sanitizer-buildbot5" ]]; then
 apt-get install -y \
  git \
  libtool \
  m4 \
  automake \
  libgcrypt-dev \
  liblzma-dev \
  libssl-dev \
  libgss-dev
fi

update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.gold" 20
update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.bfd" 10

mkdir -p $BOT_DIR
chown buildbot:buildbot $BOT_DIR

buildslave create-slave $BOT_DIR lab.llvm.org:9990 $BOT_NAME $BOT_PASS

echo "Vitaly Buka <vitalybuka@google.com>" > $BOT_DIR/info/admin

uname -a | head -n1 > $BOT_DIR/info/host
cmake --version | head -n1 >> $BOT_DIR/info/host
g++ --version | head -n1 >> $BOT_DIR/info/host
ld --version | head -n1 >> $BOT_DIR/info/host
date >> $BOT_DIR/info/host

echo "SLAVE_RUNNER=/usr/bin/buildslave
SLAVE_ENABLED[1]=\"1\"
SLAVE_NAME[1]=\"buildslave1\"
SLAVE_USER[1]=\"buildbot\"
SLAVE_BASEDIR[1]=\"$BOT_DIR\"
SLAVE_OPTIONS[1]=\"\"
SLAVE_PREFIXCMD[1]=\"\"" > /etc/default/buildslave

chown -R buildbot:buildbot $BOT_DIR
service buildslave restart
