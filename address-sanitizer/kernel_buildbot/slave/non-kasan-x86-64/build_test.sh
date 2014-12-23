#!/bin/bash

set -eux

echo @@@BUILD_STEP Make Kernel@@@
echo

#make clean

make defconfig
make kvmconfig
cat ../add_config >> .config

make LOCALVERSION=-asan CC=../../../gcc_install/bin/gcc -j64

mkdir -p mod_install
rm -rf mod_install/*
INSTALL_MOD_PATH=mod_install make modules_install LOCALVERSION=-asan CC=../../../gcc_install/bin/gcc
chmod -R a+rwx mod_install

echo @@@BUILD_STEP Boot VM@@@
echo

cp -f ../../../wheezy.img wheezy-dirty.img

rm -f vm_pid

BOOT_START=$(date +%s.%N)

qemu-system-x86_64 \
  -hda wheezy-dirty.img \
  -m 4G -smp 4 \
  -net user,hostfwd=tcp::10122-:22 -net nic \
  -nographic \
  -kernel arch/x86/boot/bzImage -append "console=ttyS0 root=/dev/sda debug earlyprintk=serial slub_debug=QUZ"\
  -virtfs local,id=r,path=mod_install,security_model=none,writeout=immediate,mount_tag=mount_host \
  -enable-kvm \
  -pidfile vm_pid \
  > vm_log &

sleep 10

trap "kill $(cat vm_pid); cat vm_log; exit 1" EXIT

kill -0 $(cat vm_pid)

( timeout 70 tail -n +0 -f vm_log &) | timeout 60 grep -q "Starting.*sshd"

BOOT_FINISH=$(date +%s.%N)
BOOT_TIME=$(echo "$BOOT_FINISH - $BOOT_START" | bc)

echo @@@STEP_TEXT@boot time: $BOOT_TIME@@@

cp -rf ../../../ssh ./
ssh -v -i ssh/id_rsa -p 10122 -o ConnectionAttempts=10 -o ConnectTimeout=60 root@localhost "uname -a"

echo @@@BUILD_STEP Benchmarks@@@

scp -i ssh/id_rsa -P 10122 ../../bench_pipes.c root@localhost:~/
ssh -i ssh/id_rsa -p 10122 root@localhost "gcc -pthread -o bench_pipes bench_pipes.c"
ssh -i ssh/id_rsa -p 10122 root@localhost "/usr/bin/time -p ./bench_pipes 16 1024 8 " 2> bench1
echo @@@STEP_TEXT@ALLOC $(grep "sys" bench1) @@@

scp -i ssh/id_rsa -P 10122 ../../bench_readv.c root@localhost:~/
ssh -i ssh/id_rsa -p 10122 root@localhost "gcc -pthread -o bench_readv bench_readv.c"
ssh -i ssh/id_rsa -p 10122 root@localhost "dd of=temp if=/dev/urandom bs=1K count=1"
ssh -i ssh/id_rsa -p 10122 root@localhost "/usr/bin/time -p ./bench_readv temp 64000 8" 2> bench2

echo @@@STEP_TEXT@ACCESS $(grep "sys" bench2) @@@

echo @@@BUILD_STEP Run Trinity@@@
echo

ssh -i ssh/id_rsa -p 10122 root@localhost "trinity -C 20 -N 20000 -s 27 --dropprivs"

echo @@@BUILD_STEP VM Log@@@
echo

kill $(cat vm_pid)

trap "" EXIT

cat vm_log


