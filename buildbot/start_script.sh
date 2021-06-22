#!/bin/bash

# Script to configure GCE instance to run sanitizer build bots.

# NOTE: GCE can wait up to 20 hours before reloading this file.
# If some instance needs changes sooner just shutdown the instance 
# with GCE UI or "sudo shutdown now" over ssh. GCE will recreate
# the instance and reload the script.

MASTER_PORT=${MASTER_PORT:-9994}
API_PORT=${API_PORT:-8014}
ON_ERROR=${ON_ERROR:-shutdown now}

BOT_DIR=/b

SCRIPT_DIR=$(dirname $(readlink -f "$0"))

#mount -t tmpfs tmpfs /tmp
mkdir -p $BOT_DIR
#mount -t tmpfs tmpfs -o size=80% $BOT_DIR

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
      apt-key adv --recv-keys --keyserver keyserver.ubuntu.com FEEA9169307EA071 || exit 1
      apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 871920D1991BC93C || exit 1

      dpkg --add-architecture i386
      echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
      dpkg --configure -a
      apt-get -qq -y update || exit 1
      #apt-get -qq -y upgrade
      
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
        libstdc++-8-dev-*-cross \
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
bash add-monitoring-agent-repo.sh --also-install
sudo service stackdriver-agent start

update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.gold" 20
update-alternatives --install "/usr/bin/ld" "ld" "/usr/bin/ld.bfd" 10

#mkdir -p $BOT_DIR/.ccache
#cache_dir = $BOT_DIR/.ccache
mkdir -p /var/lib/buildbot/.ccache
chown -R buildbot:buildbot /var/lib/buildbot/.ccache
cat <<EOF >/var/lib/buildbot/.ccache/ccache.conf
max_size = 20.0G
compression = true
EOF

# Generate Debian image for QEMU bot.
(
  set -ux
  rm -rf $BOT_DIR/qemu_image
  mkdir -p $BOT_DIR/qemu_image
  cd $BOT_DIR/qemu_image

  SLEEP=0
  for i in `seq 1 5`; do
    sleep $SLEEP
    SLEEP=$(( SLEEP + 10))
    ${SCRIPT_DIR}/../hwaddress-sanitizer/create_qemu_image.sh && exit 0
  done
  exit 1
) || $ON_ERROR

function create_worker() {
  local WORKER_NAME="$1"
  local SERVICE_NAME=buildbot-worker@b.service
  [[ -d /var/lib/buildbot/workers/b ]] || ln -s $BOT_DIR /var/lib/buildbot/workers/b

  systemctl enable $SERVICE_NAME
  systemctl set-property $SERVICE_NAME TasksMax=100000

  systemctl stop $SERVICE_NAME || true
  while pkill buildbot-worker; do sleep 5; done;

  rm -f ${BOT_DIR}/buildbot.tac ${BOT_DIR}/twistd.log
  buildbot-worker create-worker -f --allow-shutdown=signal $BOT_DIR lab.llvm.org:$MASTER_PORT \
    "$WORKER_NAME" \
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

  chown -R buildbot:buildbot $BOT_DIR
  systemctl daemon-reload
  systemctl start $SERVICE_NAME
  systemctl status $SERVICE_NAME
  sleep 30
  cat ${BOT_DIR}/twistd.log
  grep "worker is ready" $BOT_DIR/twistd.log || $ON_ERROR
}

function is_worker_connected() {
  local WORKER_NAME="$1"
  (
    set -o pipefail
    curl http://lab.llvm.org:${API_PORT}/api/v2/workers/${WORKER_NAME} \
      | jq -e '.workers[] | select(.connected_to[] | length!=0)'
  )
}

#create_worker "sanitizer-$(hostname | cut -d '-' -f2)"
function try_worker() {
  local WORKER_NAME="$1"
  is_worker_connected ${WORKER_NAME} && return 1
  create_worker "$WORKER_NAME"
  sleep 30
  while is_worker_connected ${WORKER_NAME} | grep " $HOSTNAME " ; do
    sleep 900
  done
  return 0
}

while true ; do
  for W in 1 3 7 2 4 8 ; do
    try_worker "sanitizer-buildbot${W}" && break
  done
done
