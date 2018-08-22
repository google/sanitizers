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
 libxml2-dev
 
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
 
apt-get remove -y --purge buildbot-slave
while pkill -SIGHUP buildslave; do sleep 5; done;
apt-get install -y buildbot-slave

rm -rf $BOT_DIR/*
chown buildbot:buildbot $BOT_DIR

update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.gold" 20
update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.bfd" 10

systemctl set-property buildslave.service TasksMax=100000

function try_create() {
 BOT_NAME=$1
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
 service buildslave restart
}

BOT_NAME=
function claim_bot() {
  BOT_NAME=$1
  OLD_HOST="$(gsutil cat gs://sanitizer-buildbot/${BOT_NAME})"
  if [[ "$OLD_HOST" != "$HOSTNAME" ]] ; then
    if ping -c 1 "$OLD_HOST" ; then
      return 1
    fi
    if [[ "$(gsutil cat gs://sanitizer-buildbot/${BOT_NAME})" != "$OLD_HOST" ]] ; then
      return 1
    fi
    echo $HOSTNAME | gsutil cp - gs://sanitizer-buildbot/${BOT_NAME}
  fi
  sleep 10
  if [[ "$(gsutil cat gs://sanitizer-buildbot/${BOT_NAME})" != "$HOSTNAME" ]] ; then
    return 1
  fi
  echo "$BOT_NAME is claimed"
}



# Order is important.
# 1,2,3,7 are primary bots, 4,5,8 are backups.
#claim_bot sanitizer-buildbot1 || \
#claim_bot sanitizer-buildbot2 || \
claim_bot sanitizer-buildbot3 || \
claim_bot sanitizer-buildbot7 || \
claim_bot sanitizer-buildbot4 || \
claim_bot sanitizer-buildbot8 || \
#claim_bot sanitizer-buildbot5 || \
shutdown now

try_create $BOT_NAME

ShutdownIfNotAlive 30

# GCE can restart instance after 24h in the middle of the build.
# Gracefully restart before that happen.
sleep 72000
while pkill -SIGHUP buildslave; do sleep 5; done;
shutdown now
