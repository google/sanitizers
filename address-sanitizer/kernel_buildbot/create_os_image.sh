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

# Build a disk image 
dd if=/dev/zero of=wheezy.img bs=1M seek=4095 count=1
mkfs.ext4 -F wheezy.img
sudo mkdir -p /mnt/wheezy
sudo mount -o loop wheezy.img /mnt/wheezy
sudo cp -a wheezy/. /mnt/wheezy/.
sudo umount /mnt/wheezy


