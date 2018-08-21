#!/bin/bash

# NOTE: GCE can wait up to 20 hours before reloading this file.
# If some instance needs changes sooner just shutdown the instance 
# with GCE UI or "sudo shutdown now" over ssh. GCE will recreate
# the instance and reload the script.

function ShutdownIfNotAlive() {
  sleep $1
  pgrep buildslave || shutdown now
}

ShutdownIfNotAlive 300 &

BOT_DIR=/b
BOT_PASS=$1

mount -t tmpfs tmpfs /tmp
mkdir -p $BOT_DIR
mount -t tmpfs tmpfs -o size=80% $BOT_DIR

curl "https://repo.stackdriver.com/stack-install.sh" | bash -s -- --write-gcm

dpkg --add-architecture i386
apt-get update -y
apt-get upgrade -y

apt-get install -y buildbot-slave
 
apt-get install -y \
 subversion \
 g++ \
 cmake \
 binutils-gold \
 binutils-dev \
 ninja-build \
 pkg-config \
 gcc-multilib \
 g++-multilib \
 gawk \
 libxml2-dev \
 jq
 
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

function try_create() {
 BOT_NAME=$1
 echo "Creating $BOT_NAME"
 if curl http://lab.llvm.org:8011/json/slaves/${BOT_NAME} | jq ".connected" | grep "true" ; then
   echo "$BOT_NAME is already connected"
   return 1
 fi

 rm -rf $BOT_DIR/*
 chown buildbot:buildbot $BOT_DIR
 buildslave create-slave --allow-shutdown=signal $BOT_DIR lab.llvm.org:9990 $BOT_NAME $BOT_PASS

 echo "Vitaly Buka <vitalybuka@google.com>" > $BOT_DIR/info/admin

 {
   uname -a | head -n1
   cmake --version | head -n1
   g++ --version | head -n1
   ld --version | head -n1
   date
 } > $BOT_DIR/info/host

 echo "SLAVE_RUNNER=/usr/bin/buildslave
 SLAVE_ENABLED[1]=\"1\"
 SLAVE_NAME[1]=\"buildslave1\"
 SLAVE_USER[1]=\"buildbot\"
 SLAVE_BASEDIR[1]=\"$BOT_DIR\"
 SLAVE_OPTIONS[1]=\"\"
 SLAVE_PREFIXCMD[1]=\"\"" > /etc/default/buildslave

 chown -R buildbot:buildbot $BOT_DIR
 systemctl daemon-reload
 if service buildslave restart ; then
   sleep 30
   if curl http://lab.llvm.org:8011/json/slaves/${BOT_NAME} | jq ".host" | grep " $BOT_NAME " ; then
     echo "$BOT_NAME is connected"
     return 0
   else
     echo "Another builder claimed $BOT_NAME"
     return 1
   fi
 else
   echo "Failed to restart $BOT_NAME"
   return 1
 fi
}

# Order is important.
# 1,2,3,7 are primary bots, 4,5,8 are backups.
try_create sanitizer-buildbot1 || \
try_create sanitizer-buildbot2 || \
try_create sanitizer-buildbot3 || \
try_create sanitizer-buildbot7 || \
try_create sanitizer-buildbot4 || \
try_create sanitizer-buildbot8 || \
try_create sanitizer-buildbot5 
#|| shutdown now

ShutdownIfNotAlive 30

# GCE can restart instance after 24h in the middle of the build.
# Gracefully restart before that happen.
sleep 72000
while pkill -SIGHUP buildslave; do sleep 5; done;
shutdown now
