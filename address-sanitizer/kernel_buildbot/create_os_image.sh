#!/bin/bash

# Create a minimal Debian-wheezy distributive as a directory
set -eux

mkdir -p wheezy
sudo rm -rf wheezy/*
sudo debootstrap --include=openssh-server wheezy wheezy

# Enable promtless ssh to the machine for root with RSA keys
sudo sed -i '/^root/ { s/:x:/::/ }' wheezy/etc/passwd
echo 'V0:23:respawn:/sbin/getty 115200 hvc0' | sudo tee -a wheezy/etc/inittab
printf '\nauto eth0\niface eth0 inet dhcp\n' | sudo tee -a wheezy/etc/network/interfaces
sudo mkdir wheezy/root/.ssh/
mkdir -p ssh
rm -rf ssh/*
ssh-keygen -f ssh/id_rsa -t rsa -N ''
cat ssh/id_rsa.pub | sudo tee wheezy/root/.ssh/authorized_keys

# Download and install trinity and other utils
sudo chroot wheezy /bin/bash -c "apt-get update; ( yes | apt-get install curl tar gcc make  sysbench time )"
sudo chroot wheezy /bin/bash -c "mkdir -p ~; cd ~/ ; curl http://codemonkey.org.uk/projects/trinity/trinity-1.4.tar.xz -o trinity-1.4.tar.xz ; tar -xf trinity-1.4.tar.xz"
sudo chroot wheezy /bin/bash -c "cd ~/trinity-1.4 ; ./configure.sh ; make -j16 ; make install"

# Build a disk image 
dd if=/dev/zero of=wheezy.img bs=1M seek=511 count=1
mkfs.ext4 -F wheezy.img
sudo mkdir -p /mnt/wheezy
sudo mount -o loop wheezy.img /mnt/wheezy
sudo cp -a wheezy/. /mnt/wheezy/.
sudo umount /mnt/wheezy

