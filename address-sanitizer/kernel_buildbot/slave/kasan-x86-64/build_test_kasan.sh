#!/bin/bash

set -eux

echo @@@BUILD_STEP Make Kernel@@@
echo

make clean

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
qemu-system-x86_64 \
  -hda wheezy-dirty.img \
  -m 4G -smp 4 \
  -net user,hostfwd=tcp::10022-:22 -net nic \
  -nographic \
  -kernel arch/x86/boot/bzImage -append "console=ttyS0 root=/dev/sda debug earlyprintk=serial slub_debug=QZ"\
  -virtfs local,id=r,path=mod_install,security_model=none,writeout=immediate,mount_tag=mount_host \
  -enable-kvm \
  -pidfile vm_pid \
  > vm_log &

sleep 10

trap "kill $(cat vm_pid); cat vm_log; exit 1" EXIT

kill -0 $(cat vm_pid)

( tail -n +0 -f vm_log &) | timeout 600 grep -q "Starting.*sshd"

cp -rf ../../../ssh ./
ssh -v -i ssh/id_rsa -p 10022 -o ConnectionAttempts=10 -o ConnectTimeout=60 root@localhost "uname -a"

echo @@@BUILD_STEP Run Tests@@@
echo

ssh -i ssh/id_rsa -p 10022 root@localhost "mkdir -p mod_install && mount -t 9p -o trans=virtio mount_host mod_install/ -oversion=9p2000.L,posixacl,cache=loose"
ssh -i ssh/id_rsa -p 10022 root@localhost "for run in {1..30}; do insmod mod_install/lib/modules/*/kernel/lib/test_kasan.ko || echo "test";  done"

cat vm_log | python ../../../../tools/kernel_test_parse.py --annotate --assert_candidates 5 --failed_log --allow_flaky kmalloc_oob_left

echo @@@BUILD_STEP Run Trinity@@@
echo


ssh -i ssh/id_rsa -p 10022 root@localhost "trinity -C 20 -N 20000 -s 27 --dropprivs"

echo @@@BUILD_STEP VM Log@@@
echo

kill $(cat vm_pid)

trap "" EXIT

cat vm_log

