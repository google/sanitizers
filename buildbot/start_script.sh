#!/bin/bash

# Script to configure GCE instance to run sanitizer build bots.

# NOTE: GCE can wait up to 20 hours before reloading this file.
# If some instance needs changes sooner just shutdown the instance 
# with GCE UI or "sudo shutdown now" over ssh. GCE will recreate
# the instance and reload the script.

MASTER_PORT=${MASTER_PORT:-9990}
ON_ERROR=${ON_ERROR:-shutdown now}

BOT_DIR=/b

mount -t tmpfs tmpfs /tmp
mkdir -p $BOT_DIR
mount -t tmpfs tmpfs -o size=80% $BOT_DIR

(
  SLEEP=0
  for i in `seq 1 5`; do
    sleep $SLEEP
    SLEEP=$(( SLEEP + 10))

    (
      set -ex
      dpkg --add-architecture i386
      echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
      dpkg --configure -a
      apt-get -qq -y update
      #apt-get -qq -y upgrade

      # Logs consume a lot of storage space.
      apt-get remove -qq -y --purge auditd puppet-agent google-fluentd

      apt-get install -qq -y \
        g++ \
        cmake \
        ccache \
        binutils-gold \
        binutils-dev \
        ninja-build \
        pkg-config \
        gcc-multilib \
        g++-multilib \
        gawk \
        dos2unix \
        libxml2-dev \
        rsync \
        git \
        libtool \
        m4 \
        automake \
        libgcrypt-dev \
        liblzma-dev \
        libssl-dev \
        libgss-dev \
        python-dev \
        python3-distutils \
        python-psutil \
        python3-psutil \
        wget \
        zlib1g-dev \
        libtinfo5 \
        libtinfo-dev \
        buildbot-worker

    ) && exit 0
  done
  exit 1
) || $ON_ERROR

update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.gold" 20
update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.bfd" 10

SERVICE_NAME=buildbot-worker@b.service
[[ -d /var/lib/buildbot/workers/b ]] || ln -s $BOT_DIR /var/lib/buildbot/workers/b

systemctl enable $SERVICE_NAME
systemctl set-property $SERVICE_NAME TasksMax=100000

systemctl stop $SERVICE_NAME || true
while pkill buildworker; do sleep 5; done;

rm -f /b/buildbot.tac
buildbot-worker create-worker -f --allow-shutdown=signal $BOT_DIR lab.llvm.org:$MASTER_PORT \
  "sanitizer-$(hostname | cut -d '-' -f2)" \
  "$(gsutil cat gs://sanitizer-buildbot/buildbot_password)"


echo "Vitaly Buka <vitalybuka@google.com>" > $BOT_DIR/info/admin

{
  echo "How to reproduce locally: https://github.com/google/sanitizers/wiki/SanitizerBotReproduceBuild"
  echo
  uname -a | head -n1
  date
  cmake --version | head -n1
  g++ --version | head -n1
  ld --version | head -n1
  lscpu
} > $BOT_DIR/info/host

mkdir -p /var/lib/buildbot/.ccache/
chown -R buildbot:buildbot /var/lib/buildbot/.ccache
cat <<EOF >/var/lib/buildbot/.ccache/ccache.conf
max_size = 20.0G
compression = true
EOF

chown -R buildbot:buildbot $BOT_DIR
systemctl daemon-reload
systemctl start $SERVICE_NAME
systemctl status $SERVICE_NAME

sleep 30
cat $BOT_DIR/twistd.log
grep "worker is ready" $BOT_DIR/twistd.log || $ON_ERROR

# GCE can restart instance after 24h in the middle of the build.
# Gracefully restart before that happen.
sleep 72000
while pkill -SIGHUP buildslave; do sleep 5; done;
$ON_ERROR
