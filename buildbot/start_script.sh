#!/bin/bash

# Script to configure GCE instance to run sanitizer build bots.

# NOTE: GCE can wait up to 20 hours before reloading this file.
# If some instance needs changes sooner just shutdown the instance
# with GCE UI or "sudo shutdown now" over ssh. GCE will recreate
# the instance and reload the script.

if [[ -v USE_STAGING ]] ; then
  SERVER_PORT=9994
  API_URL=https://lab.llvm.org/staging/api/v2/workers
else
  SERVER_PORT=9990
  API_URL=https://lab.llvm.org/buildbot/api/v2/workers
fi

ON_ERROR=${ON_ERROR:-shutdown now}
BOT_DIR=/b
QEMU_IMAGE_DIR=${BOT_DIR}/qemu_image
SCRIPT_DIR=$(dirname $(readlink -f "$0"))

${SCRIPT_DIR}/install_deps.sh

# Generate Debian image for QEMU bot.
(
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
  
  $ON_ERROR
) &

function create_worker() {
  local WORKER_NAME="$1"
  local SERVICE_NAME=buildbot-worker@b.service
  [[ -d /var/lib/buildbot/workers/b ]] || ln -s $BOT_DIR /var/lib/buildbot/workers/b

  systemctl set-property $SERVICE_NAME TasksMax=100000
  mkdir -p /etc/systemd/system/${SERVICE_NAME}.d
  cat <<EOF >/etc/systemd/system/${SERVICE_NAME}.d/limits.conf
[Service]
LimitNOFILE=1048576:1048576
EOF
  

   
  systemctl stop $SERVICE_NAME || true
  while pkill buildbot-worker; do sleep 5; done;

  rm -f ${BOT_DIR}/buildbot.tac ${BOT_DIR}/twistd.log
  buildbot-worker create-worker -f --allow-shutdown=signal $BOT_DIR lab.llvm.org:$SERVER_PORT \
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
    echo "Host: $(hostname -f)"
  } > $BOT_DIR/info/host

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
  ) | grep " $HOSTNAME "
}

function claim_worker() {
  local WORKER_NAME="$1"
  #is_worker_connected ${WORKER_NAME} && return 1
  create_worker "$WORKER_NAME" || return 2
  sleep 30
  while is_worker_myself ${WORKER_NAME} ; do
    sleep 900
  done
  # Notify caller that we've seen at least 1 disconnected worker.
  return 0
}

BOTS=$(echo "1 3 7 2 4 8" | tr ' ' '\n' | shuf)
while true ; do
  sleep 30
  (
    # Try claim the same bot.
    for W in $BOTS ; do
      [[ "$(get_worker_host sanitizer-buildbot${W})" == "$HOSTNAME" ]] || continue
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
