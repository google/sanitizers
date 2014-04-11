set -xe
CLANG_BIN=path_to_clang
JOBS=-j32
SERVER_PORT=8080

function build_dir {
  echo "build-$1"
}

function fix_config {
  config=conf/httpd.conf
  cp $config $config.orig
  cat $config.orig | sed "s/Listen 80$/Listen $SERVER_PORT/" > $config
}

function configure_make_install {
  make $JOBS clean || true
  builddir=$(build_dir $1)
  custom_cflags=$2
  if [ "$1" == "tsan-v2" ]; then
    ./configure CC=$CLANG_BIN/clang CFLAGS="-fPIC -fsanitize=thread -gline-tables-only $custom_cflags" LDFLAGS='-pie -fsanitize=thread -gline-tables-only' --prefix=`pwd`/$builddir
  elif [ "$1" == "clang" ]; then
    ./configure CC=$CLANG_BIN/clang CFLAGS='-gline-tables-only' LDFLAGS='-gline-tables-only' --prefix=`pwd`/$builddir
  fi
  make $JOBS && make $JOBS install
}

function build_httpd {
  configure_make_install $1
  pushd $builddir
  fix_config
  popd
}

function run_ab() {
  $(build_dir clang)/bin/ab -n 30000 -c 20 http://127.0.0.1:$SERVER_PORT/
}

function test_httpd {
  builddir=$(build_dir $1)
  pushd $builddir
  if [ "$1" == "tsan-v2" ]; then
    export TSAN_OPTIONS="external_symbolizer_path=$CLANG_BIN/llvm-symbolizer"
  fi
  # Make sure our httpd is not running. Won't help against httpds running
  # from other server dirs.
  bin/httpd -k stop
  bin/httpd
  popd
  run_ab 2>&1 | tee "$1-ab.log"
  pushd $builddir
  bin/httpd -k stop
  sleep 1
  bin/httpd -k stop
  popd
}

build_httpd clang
build_httpd tsan-v2

test_httpd clang
test_httpd tsan-v2
