#!/bin/bash

set -eux

echo @@@BUILD_STEP Make Kernel@@@
echo

make clean

make defconfig
make kvmconfig
cat add_config >> .config

make LOCALVERSION=-asan CC=/media/bigdisk/dmitryc/kasan/gcc/gcc_install/bin/gcc -j64

mkdir -p mod_install
rm -rf mod_install/*
INSTALL_MOD_PATH=mod_install make modules_install LOCALVERSION=-asan
chmod -R a+rwx mod_install

echo @@@BUILD_STEP Boot VM@@@
echo

cp -f ../../../wheezy.img wheezy-dirty.img

qemu-system-x86_64 \
  -hda wheezy-dirty.img \
  -m 4G -smp 4 \
  -net user,hostfwd=tcp::10022-:22 -net nic \
  -nographic \
  -kernel arch/x86/boot/bzImage -append "console=ttyS0 root=/dev/sda debug earlyprintk=serial"\
  -virtfs local,id=r,path=mod_install,security_model=none,writeout=immediate,mount_tag=mount_host \
  -enable-kvm \
  > vm_log &

VM_PID=$!

trap "killall qemu-system-x86_64 ; cat vm_log; exit 1" EXIT

sleep 1

kill -0 $VM_PID

cp -rf ../../../ssh ./

ssh -v -i ssh/id_rsa -p 10022 -o ConnectionAttempts=10 -o ConnectTimeout=60 root@localhost "uname -a"

echo @@@BUILD_STEP Run Tests@@@
echo

ssh -i ssh/id_rsa -p 10022 root@localhost "mkdir -p mod_install && mount -t 9p -o trans=virtio mount_host mod_install/ -oversion=9p2000.L,posixacl,cache=loose"
ssh -i ssh/id_rsa -p 10022 root@localhost "insmod mod_install/lib/modules/*/kernel/lib/test_kasan.ko" &> insmod_log || grep "Resource temporarily unavailable" insmod_log


echo @@@BUILD_STEP VM Log@@@
echo

cat vm_log

kill $VM_PID
killall qemu-system-x86_64

trap "" EXIT




