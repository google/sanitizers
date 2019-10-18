#!/bin/bash

# Script to configure GCE instance to run sanitizer build bots.

# NOTE: GCE can wait up to 20 hours before reloading this file.
# If some instance needs changes sooner just shutdown the instance 
# with GCE UI or "sudo shutdown now" over ssh. GCE will recreate
# the instance and reload the script.

MASTER_PORT=${MASTER_PORT:-9990}

BOT_DIR=/b

mount -t tmpfs tmpfs /tmp
mkdir -p $BOT_DIR
mount -t tmpfs tmpfs -o size=80% $BOT_DIR

dpkg --add-architecture i386
apt-get update -yq

curl "https://repo.stackdriver.com/stack-install.sh" | bash -s -- --write-gcm

# Logs consume a lot of storage space.
apt-get remove -yq --purge auditd puppet-agent google-fluentd

apt-get install -yq \
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
 dos2unix \
 libxml2-dev || shutdown now
 
# Only for fuzzing
apt-get install -yq \
 git \
 libtool \
 m4 \
 automake \
 libgcrypt-dev \
 liblzma-dev \
 libssl-dev \
 libgss-dev || shutdown now
 
buildslave stop $BOT_DIR
apt-get remove -yq --purge buildbot-slave
apt-get install -yq buildbot-slave

update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.gold" 20
update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.bfd" 10

systemctl set-property buildslave.service TasksMax=100000

chown buildbot:buildbot $BOT_DIR

buildslave create-slave --allow-shutdown=signal $BOT_DIR lab.llvm.org:$MASTER_PORT \
  "sanitizer-$(hostname | cut -d '-' -f2)" \
  "$(gsutil cat gs://sanitizer-buildbot/buildbot_password)"

echo "Vitaly Buka <vitalybuka@google.com>" > $BOT_DIR/info/admin

{
  echo "How to reproduce locally: https://github.com/google/sanitizers/wiki/SanitizerBotReproduceBuild"
  echo
  uname -a | head -n1
  cmake --version | head -n1
  g++ --version | head -n1
  ld --version | head -n1
  date
  lscpu
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

sleep 30
cat $BOT_DIR/twistd.log
grep "slave is ready" $BOT_DIR/twistd.log || shutdown now

# GCE can restart instance after 24h in the middle of the build.
# Gracefully restart before that happen.
sleep 72000
while pkill -SIGHUP buildslave; do sleep 5; done;
shutdown now
