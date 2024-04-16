#!/bin/bash

# Script to configure GCE instance to run sanitizer build bots.

# NOTE: GCE can wait up to 20 hours before reloading this file.
# If some instance needs changes sooner just shutdown the instance
# with GCE UI or "sudo shutdown now" over ssh. GCE will recreate
# the instance and reload the script.

USE_STAGING=${USE_STAGING:-1}
SHUTDOWN_ON_ERROR=${SHUTDOWN_ON_ERROR:-0}

if [[ "${USE_STAGING}" == "1" ]] ; then
  SERVER_PORT=9994
  API_URL=https://lab.llvm.org/staging/api/v2/workers
else
  SERVER_PORT=9990
  API_URL=https://lab.llvm.org/buildbot/api/v2/workers
fi

if [[ "${SHUTDOWN_ON_ERROR}" == "1" ]] ; then
  ON_ERROR=${ON_ERROR:-shutdown now}
else
  ON_ERROR=${ON_ERROR:-echo "FAILED"}
fi

BOT_DIR=/b
QEMU_IMAGE_DIR=${BOT_DIR}/qemu_image
SCRIPT_DIR=$(dirname $(readlink -f "$0"))
FULL_HOSTNAME="$(hostname -f)"

mountpoint /tmp     || mount -o nosuid -t tmpfs tmpfs /tmp || $ON_ERROR

${SCRIPT_DIR}/install_deps.sh

# Optional, ingore if it fails.
curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh
bash add-google-cloud-ops-agent-repo.sh --also-install

mkdir -p $BOT_DIR
if lsblk /dev/nvme0n2 ; then
  # Format and mount scratch drive.
  [[ -e /dev/md0 ]] || {
    yes | mdadm --create /dev/md0 --level=0 -q -f --raid-devices=$(ls /dev/nvme*n* | wc -l) /dev/nvme*n*
    mkfs.xfs /dev/md0
  }
  mountpoint $BOT_DIR || mount -o nosuid /dev/md0 $BOT_DIR || $ON_ERROR
fi

# Move home to the scratch drive.
usermod -d $BOT_DIR buildbot

# Make sure .cache/clang/ModuleCache/ does not grow over time.
rm -rf $BOT_DIR/.cache

mkdir -p $BOT_DIR/.ccache
cat <<EOF >$BOT_DIR/.ccache/ccache.conf
max_size = 200.0G
compression = true
EOF

chown -R buildbot:buildbot $BOT_DIR

# Suppress dmesg spam "Pid <N>(qemu-aarch64) over core_pipe_limit".
cat <<EOF >/etc/sysctl.d/999-buildbot.conf
fs.suid_dumpable = 0
kernel.core_pipe_limit = 0
kernel.panic_on_oops = 0
kernel.softlockup_panic = 0
kernel.core_pattern = |/bin/false
EOF

sysctl --system

if [[ "$(arch)" == "x86_64" ]]; then
  cat <<EOF >/etc/exports
${BOT_DIR} 127.0.0.1(rw,sync,all_squash,insecure,anonuid=999,anongid=999,no_subtree_check)
EOF
  exportfs -rav

  # Generate Debian image for QEMU bot.
  (
    [[ -f ${QEMU_IMAGE_DIR}/debian.img ]] && exit 0
    set -ux
    rm -rf $QEMU_IMAGE_DIR
    mkdir -p $QEMU_IMAGE_DIR
    cd $QEMU_IMAGE_DIR

    SLEEP=0
    for i in `seq 1 5`; do
      sleep $SLEEP
      SLEEP=$(( SLEEP + 10 ))
      ${SCRIPT_DIR}/../hwaddress-sanitizer/create_qemu_image.sh && {
        chown -R buildbot:buildbot $QEMU_IMAGE_DIR
        exit 0
      }
    done
    exit 1
  ) || $ON_ERROR
fi

function create_worker() {
  local WORKER_NAME="$1"
  local SERVICE_NAME=buildbot-worker@b.service

  echo "Connecting as $WORKER_NAME"

  systemctl set-property $SERVICE_NAME TasksMax=100000
  mkdir -p /etc/systemd/system/${SERVICE_NAME}.d
  cat <<EOF >/etc/systemd/system/${SERVICE_NAME}.d/limits.conf
[Service]
LimitNOFILE=1048576:1048576
EOF
  
  systemctl stop $SERVICE_NAME || true
  while pkill buildbot-worker; do sleep 5; done;
  rm -f ${BOT_DIR}/twistd.log ${BOT_DIR}/buildbot.tac

  buildbot-worker create-worker -f --allow-shutdown=signal ${BOT_DIR} lab.llvm.org:$SERVER_PORT \
    "$WORKER_NAME" \
    "$(gsutil cat gs://sanitizer-buildbot/buildbot_password)"

  mkdir -p /var/lib/buildbot/workers/b
  ln -fs $BOT_DIR/buildbot.tac /var/lib/buildbot/workers/b/

  echo "Vitaly Buka <vitalybuka@google.com>" > ${BOT_DIR}/info/admin

  {
    echo "How to reproduce locally: https://github.com/google/sanitizers/wiki/SanitizerBotReproduceBuild"
    echo
    uname -a | head -n1
    date
    cmake --version | head -n1
    g++ --version | head -n1
    ld --version | head -n1
    lscpu
    echo "Host: ${FULL_HOSTNAME}"
  } > ${BOT_DIR}/info/host

  chown -R buildbot:buildbot $BOT_DIR

  systemctl daemon-reload
  systemctl start $SERVICE_NAME
  systemctl status $SERVICE_NAME
  sleep 30
  cat ${BOT_DIR}/twistd.log
  grep "worker is ready" $BOT_DIR/twistd.log
}

function is_worker_connected() {
  local WORKER_NAME="$1"
  (
    set -o pipefail
    curl ${API_URL}/${WORKER_NAME} \
      | jq -e '.workers[] | select(.connected_to[] | length!=0)'
  )
}

function get_worker_host() {
  local WORKER_NAME="$1"
  (
    set -o pipefail
    curl ${API_URL}/${WORKER_NAME} \
      | jq -re '.workers[].workerinfo.host | capture("(?<p>Host): *(?<v>.*)").v'
  )
}

function is_worker_myself() {
  local WORKER_NAME="$1"
  (
    for i in `seq 1 5`; do
      is_worker_connected ${WORKER_NAME} && exit 0
      sleep 30
    done
    exit 1
  ) | grep " ${FULL_HOSTNAME}"
}

function shutdown_maybe() {
  [[ $(cat /proc/uptime | grep -oP "^\d+") -lt 3600 ]] && return
  #(w -h | wc -l) && return
  while sudo pkill -SIGHUP buildbot-worker; do sleep 5; done;
  shutdown now
}

function claim_worker() {
  local WORKER_NAME="$1"
  #is_worker_connected ${WORKER_NAME} && return 1
  create_worker "$WORKER_NAME" || return 2
  sleep 30
  while is_worker_myself ${WORKER_NAME} ; do
    shutdown_maybe
    sleep 900
  done
  # Notify caller that we've seen at least 1 disconnected worker.
  return 0
}

if [[ "$(arch)" == "x86_64" ]]; then
  BOTS="1 2 3 4 5 6"
else
  BOTS="7 8 9 10 11 12"
fi
BOTS=$(echo "$BOTS" | tr ' ' '\n' | shuf)
while true ; do
  sleep 30
  (
    # Try claim the same bot.
    for W in $BOTS ; do
      [[ "$(get_worker_host sanitizer-buildbot${W})" == "${FULL_HOSTNAME}" ]] || continue
      claim_worker "sanitizer-buildbot${W}" && exit
    done

    # Ignore bots with online hosts.
    for W in $BOTS ; do
      ping "$(get_worker_host sanitizer-buildbot${W})" -c3 && continue
      claim_worker "sanitizer-buildbot${W}" && exit
    done

    for W in $BOTS ; do
      claim_worker "sanitizer-buildbot${W}" && exit
    done

    # No unclaimed workers?
    $ON_ERROR
  )
done
