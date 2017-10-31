#!/bin/bash

BOT_DIR=/b
BOT_NAME=$1
BOT_PASS=$2

mount -t tmpfs tmpfs /tmp
mkdir -p $BOT_DIR
mount -t tmpfs tmpfs -o size=80% $BOT_DIR

curl "https://repo.stackdriver.com/stack-install.sh" | bash -s -- --write-gcm

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
 
# Only for fuzzing
apt-get install -y \
 git \
 libtool \
 m4 \
 automake \
 libgcrypt-dev \
 liblzma-dev \
 libssl-dev \
 libgss-dev

update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.gold" 20
update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.bfd" 10

systemctl set-property buildslave.service TasksMax=100000

chown buildbot:buildbot $BOT_DIR

buildslave create-slave --allow-shutdown=signal $BOT_DIR lab.llvm.org:9990 $BOT_NAME $BOT_PASS

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
systemctl daemon-reload
service buildslave restart

sleep 30
pgrep buildslave || shutdown now

# GCE can restart instance after 24h in the middle of the build.
# Gracefully restart before that happen.
sleep 72000
while pkill -SIGHUP buildslave; do sleep 5; done;
shutdown now
