#!/bin/sh

# --------- Settings block ----

LIBRARIES=(libdbus-1-3 libgdk-pixbuf2.0-0 libdbus-glib-1-2 libatk1.0-0 libgconf-2-4 libgtk2.0-0
           libpng12-0 libpango1.0-0 libfreetype6 libudev0 libx11-6
           zlib1g libcairo2 libxau6 libxrandr2 libxss1
           libxext6 libxi6 libxtst6 libexpat1 libffi6
           libfontconfig1 libxinerama1 libxrender1 libxcb1
           libpixman-1-0 libxcomposite1 libxcursor1 libxdamage1
           libxdmcp6 libxfixes3 libk5crypto3 libkeyutils1 libselinux1
           libpcre3 libp11-kit0 libbz2-1.0 libgpg-error0
           libnss3 libgcrypt11 libglib2.0-0 libtasn1-3 libnspr4 libgnutls26)

INSTALL_DIR=$(pwd)/asan

PATCHES_DIR=$(pwd)

# should be without spaces to pass it to dpkg-buildpackage!
MAKEJOBS="-j14"

if [ -z "$CC" ]; then
  export CC=clang
fi

if [ -z "$CXX" ]; then
  export CXX=clang++
fi

export CFLAGS="-fsanitize=address -g -fPIC -w"
export CXXFLAGS="-fsanitize=address -g -fPIC -w"
export LDFLAGS="-Wl,-z,muldefs -Wl,-z,origin -Wl,-R,XORIGIN/."


declare -A ADDITIONAL_CONFIGURE_FLAGS
ADDITIONAL_CONFIGURE_FLAGS=(
  ["libgconf-2-4"]="--with-gtk=3.0 --disable-orbit"
  ["libgdk-pixbuf2.0-0"]="--with-libjasper --with-x11 --enable-introspection"
  ["libgnutls26"]="--without-lzo --disable-guile --enable-ld-version-script --enable-cxx --with-libgcrypt"
  ["libpango1.0-0"]="--with-included-modules=yes"
)

# -----------------------------

# helpful constants and functions

red='\e[0;31m'
green='\e[0;32m'
NC='\e[0m' # No Color

function echo_red {
  echo -e "${red}$1${NC}"
}

function echo_green {
  echo -e "${green}$1${NC}"
}

# fixes rpath from XORIGIN to $ORIGIN in the single file $1
function fix_rpath {
   chrpath -r $(chrpath $1 | cut -d " " -f 2 | sed s/XORIGIN/\$ORIGIN/g | sed s/RPATH=//g) $1
}

# parsing args

while getopts ":di:ph" opt; do
  case $opt in
    d)
      echo_green "Only deleting folders"
      rm -rf $INSTALL_DIR
      rm -rf ${LIBRARIES[@]}
      echo_green Done
      exit
      ;;
    p)
      echo_green "Only installing dependencies (requires root access)"
      for lib in ${LIBRARIES[@]}
      do
        echo_green "Installing all dependencies: $lib"
        sudo apt-get -y --no-remove build-dep $lib
      done
      exit
      ;;
    h)
     echo "Possible flags: -d - delete temporary folders, -p - install dependencies for packages, -h - this help, -i - sets relative INSTALL_DIR."
     echo "Affected envs: CC and CXX"
     exit
     ;;
    i)
     INSTALL_DIR="$(pwd)/$OPTARG"
     ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit
      ;;
  esac
done

# ----- main script body

START_TIME=$(date +%s)

function default_workflow {
    echo_green "Building: ${lib}"
    ./configure --prefix=$INSTALL_DIR ${ADDITIONAL_CONFIGURE_FLAGS[$lib]}
    make $MAKEJOBS VERBOSE=1
    echo_green "Installing: ${lib}"
    make install
}

function count_libs {
  find $INSTALL_DIR | grep "\.so$" | wc -l
}

rm -rf $INSTALL_DIR/*
rm -rf ${LIBRARIES[@]}

mkdir -p $INSTALL_DIR

for lib in ${LIBRARIES[@]}
do
  echo_green "Checking if $lib needs any dependencies..."
  NEEDED_DEPS=$(apt-get -s build-dep $lib | grep Inst | cut -d " " -f 2)
  if [ -n "$NEEDED_DEPS" ]
  then
    echo_red "Library $lib needs dependencies: $NEEDED_DEPS"
    echo_red "Please, install dependencies using: ./download_build_install -p"
    exit 1
  fi
done

LIBS_COUNTER=$(count_libs)
declare -A LIBS_COUNTERS

for lib in ${LIBRARIES[@]}
do
  (
  echo_green "Downloading: ${lib}"
  mkdir $lib
  cd $lib
  apt-get source $lib

  cd $(ls -F |grep \/$)
  make clean

  if [ "$lib" == "libfreetype6" ]
  then
    echo_red "Strange package, need additional archive extraction: ${lib}"
    ARCHIVE_NAME=$(ls . | grep "${PWD##*/}\.tar.*")
    echo_red "Trying to extract: ${ARCHIVE_NAME}"
    tar -xzf $ARCHIVE_NAME
    tar -xjf $ARCHIVE_NAME
    cp -r ${PWD##*/}/* .
    default_workflow
  elif [ "$lib" == "libkeyutils1" ]
  then   
    # THIS SECTION IS NOT WORKING YET    

    # This package has an ancient Makefile, so we need to add our CFLAGS to it
    # and set DEST_DIR to our INSTALL_DIR
    
    make CFLAGS+="$CFLAGS" DESTDIR="$INSTALL_DIR"
    make CFLAGS+="$CFLAGS" DESTDIR="$INSTALL_DIR" install
  elif [ "$lib" == "libselinux1" ]
  then
    # This package has ancient Makefile and adds -z,defs to the end of compile command
    # so we cannot override it. We well use 'sed' to replace it
    sed -i "s/z,defs/z,nodefs/g" src/Makefile
    export DESTDIR=$INSTALL_DIR
    make $MAKEJOBS
    make install
  elif [ "$lib" == "libdbus-1-3" ]
  then
    # Installing to the temporary empty dir, after that copying to INSTALL_DIR
    # That's because libdbus has problems if we have already installed shared libs
    # in the INSTALL_DIR directory
    TMP_INSTALL_DIR=$(mktemp -d)
    ./configure --prefix=$TMP_INSTALL_DIR
    make $MAKEJOBS
    make install
    cp -r $TMP_INSTALL_DIR/* $INSTALL_DIR
    rm -rf $TMP_INSTALL_DIR
  elif [ "$lib" == "libpcre3" ]
  then
    # this lib requires --enable-utf8 flag to configure command
    ./configure --prefix="$INSTALL_DIR" --enable-utf8 --enable-unicode-properties
    make $MAKEJOBS
    make install
  elif [ "$lib" == "libk5crypto3" ]
  then
    # should rename folder with "+" to "_"
    cd .. 
    FOLDERNAME=$(ls -F |grep \/$)
    mv $FOLDERNAME $(echo $FOLDERNAME | sed "s/+/_/g")
    cd $(ls -F |grep \/$)
    sed -i "s/error=uninitialized//g" src/configure # ignore compile error of initialized variable.
                                                    # the bug is already fixed
    cd src # this library has additional folder inside
    export LDFLAGS="-Wl,-z,nodefs -Wl,--unresolved-symbols=ignore-all -Wl,-z,muldefs"
    ./configure --prefix="$INSTALL_DIR"
    make $MAKEJOBS
    make install
  elif [ "$lib" == "libbz2-1.0" ]
  then
    make CC="$CC" CFLAGS="$CFLAGS" PREFIX="$INSTALL_DIR"
    make install CC="$CC" CFLAGS="$CFLAGS" PREFIX="$INSTALL_DIR"
  elif [ "$lib" == "libnss3" ]
  then
    for file in $(grep -rl "= gcc" .)
    do
      sed -i "s/= gcc/= $(echo $CC | sed "s/\//\\\\\//g") $CFLAGS/g" $file;
    done
    for file in $(grep -rl "= \-Wl,\-z,defs" .)
    do 
      sed -i "s/z,defs/z,nodefs/g" $file;
    done
    EDITOR=true dpkg-source -q --commit . gcc_replace_clang # suppress editor call
    export DEB_CFLAGS_APPEND="$CFLAGS"
    export DEB_CXXFLAGS_APPEND="$CXXFLAGS"
    dpkg-buildpackage -uc -us $MAKEJOBS
    cd .. # go to folder with deb packages
    dpkg -x $(ls libnss3_*.deb) $INSTALL_DIR
  elif [ "$lib" == "libnspr4" ]
  then
    export CC="$CC $CFLAGS"
    dpkg-buildpackage -uc -us
    cp -r debian/tmp/* $INSTALL_DIR
  elif [ "$lib" == "libgtk2.0-0" ]
  then
    export CFLAGS="$CFLAGS -Wno-return-type"
    patch -p1 -i $PATCHES_DIR/libgtk2.0-0.patch
    default_workflow
  else
    default_workflow
  fi
  )
  # here recount libs
  NEW_LIBS_COUNTER=$(count_libs)
  LIBS_ADDED=$(($NEW_LIBS_COUNTER - $LIBS_COUNTER))
  LIBS_COUNTERS[$lib]=$LIBS_ADDED
  LIBS_COUNTER=$NEW_LIBS_COUNTER
done

echo "-----------------------------------------"
# fixing rpath in all compiled libraries
for i in $(find $INSTALL_DIR | grep "\.so$")
do
  fix_rpath $i
done

END_TIME=$(date +%s)

# print libs counters:
echo "-----------------------------------------"
echo -e "so-s\tpackage"
for lib in ${!LIBS_COUNTERS[@]}
do
  COUNTER=${LIBS_COUNTERS[$lib]}
  if [ $COUNTER == 0 ]
  then 
    echo_red "$COUNTER\t$lib"
  else
    echo_green "$COUNTER\t$lib"
  fi
done

# checking our libs are ASan-ned

SHARED_LIBS=$( (
for i in $(find $INSTALL_DIR | grep "\.so$")
do
  echo_green "${i} : $(nm -D $i | grep asan_i)"
done
) | sort)

echo "-----------------------------------------"
echo "Looking for ASan symbols in compiled .so files"
echo -e "$SHARED_LIBS"
echo "-----------------------------------------"
echo "Total shared libs: $(echo -e "$SHARED_LIBS" | wc -l)"
echo "Total seconds for build: $(($END_TIME - $START_TIME))"
echo "Useful command: export LD_LIBRARY_PATH=\"$INSTALL_DIR/lib:$INSTALL_DIR/usr/lib/x86_64-linux-gnu\""
