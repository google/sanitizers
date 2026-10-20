#!/bin/bash
set -exuo pipefail

if ! which go git lighttpd; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y golang-go git curl lighttpd
  rm -f /var/www/html/index.lighttpd.html
fi

if [[ ! -f /etc/lighttpd/conf-enabled/99-no-cache.conf ]]; then
  cat << 'EOF' > /etc/lighttpd/conf-enabled/99-no-cache.conf
server.modules += ( "mod_setenv" )
setenv.set-response-header = ( "Cache-Control" => "no-cache" )
EOF
  systemctl reload lighttpd
fi

export HOME="${HOME:-/root}"
CACHE_DIR="/var/cache/sanitizer-dashboard"
REPO_DIR="${CACHE_DIR}/sanitizers"

mkdir -p "${CACHE_DIR}"
if [[ ! -f "${CACHE_DIR}/cache.json" && -f /tmp/sanitizer-dashboard/cache.json ]]; then
  cp /tmp/sanitizer-dashboard/cache.json "${CACHE_DIR}/cache.json"
fi

if ! (git -C "${REPO_DIR}" fetch --depth=1 origin master && git -C "${REPO_DIR}" reset --hard FETCH_HEAD); then
  rm -rf "${REPO_DIR}"
  git clone --depth=1 https://github.com/google/sanitizers.git "${REPO_DIR}"
fi

cd "${REPO_DIR}/dashboard"
go build -o /opt/sanitizers .

mkdir -p /var/www/html
/opt/sanitizers -cache_dir="${CACHE_DIR}" > /var/www/html/index.new.html
chmod 644 /var/www/html/index.new.html
mv -f /var/www/html/index.new.html /var/www/html/index.html
