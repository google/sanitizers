#!/bin/bash
set -euo pipefail

if ! command -v go >/dev/null || ! command -v git >/dev/null || ! command -v lighttpd >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get -qq update
  apt-get -qq install -y golang-go git curl lighttpd
  rm -f /var/www/html/index.lighttpd.html
fi

export HOME="${HOME:-/root}"
REPO_DIR="/tmp/sanitizer-dashboard/sanitizers"

if [[ ! -d "${REPO_DIR}/.git" ]]; then
  rm -rf "${REPO_DIR}"
  mkdir -p "$(dirname "${REPO_DIR}")"
  git clone --depth=1 https://github.com/google/sanitizers.git "${REPO_DIR}"
else
  git -C "${REPO_DIR}" fetch --depth=1 origin master
  git -C "${REPO_DIR}" reset --hard FETCH_HEAD
fi

cd "${REPO_DIR}/dashboard"
go build -o /opt/sanitizers .

mkdir -p /var/www/html
/opt/sanitizers > /var/www/html/index.new.html
chmod 644 /var/www/html/index.new.html
mv -f /var/www/html/index.new.html /var/www/html/index.html
