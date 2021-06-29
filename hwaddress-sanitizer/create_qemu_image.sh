#!/bin/bash -eux
#
# Creates and configures a minimal Debian image for running HWASan tests in
# QEMU with the run_in_qemu_with_lam.sh script in this directory.
#
# Usage: sudo ./create_qemu_image.sh
#
# Outputs: the QEMU image and SSH keys in the current directory.

: ${RELEASE:="buster"}
: ${PREINSTALL_PKGS:="openssh-server"}  # Comma-separated list of packages.
: ${MIRROR:="http://ftp.us.debian.org/debian"}

readonly DIR="$(mktemp -d)"
readonly IMAGE_DIR="${DIR}/${RELEASE}"

# Generate base system.
mkdir "${IMAGE_DIR}"
debootstrap --include="${PREINSTALL_PKGS}" "${RELEASE}" "${IMAGE_DIR}" \
  "${MIRROR}"

# Configure system to boot properly.
sed -i "/^root/ { s/:x:/::/ }" "${IMAGE_DIR}/etc/passwd"
echo "T0:23:respawn:/sbin/getty -L ttyS0 115200 vt100" \
  >> "${IMAGE_DIR}/etc/inittab"
printf "\nauto eth0\niface eth0 inet dhcp\n" \
  >> "${IMAGE_DIR}/etc/network/interfaces"
echo "/dev/root / ext4 defaults 0 0" >> "${IMAGE_DIR}/etc/fstab"
echo -en "127.0.0.1\tlocalhost\n" > "${IMAGE_DIR}/etc/hosts"
echo "nameserver 8.8.8.8" >> "${IMAGE_DIR}/etc/resolve.conf"
echo "debian" > "${IMAGE_DIR}/etc/hostname"

# Set up SSH.
ssh-keygen -f "debian.id_rsa" -t rsa -N ""
mkdir -p "${IMAGE_DIR}/root/.ssh/"
cat "debian.id_rsa.pub" > "${IMAGE_DIR}/root/.ssh/authorized_keys"

# Configure for HWASan tests.
mkdir -p "${IMAGE_DIR}/workspace"

# Build disk image.
dd if=/dev/zero of="debian.img" bs=1M seek=2047 count=1
mkfs.ext4 -F "debian.img"
mkdir -p "/mnt/${RELEASE}"
mount -o loop "debian.img" "/mnt/${RELEASE}"
cp -a "${IMAGE_DIR}/." "/mnt/${RELEASE}/."
umount "/mnt/${RELEASE}"
while ! rm -rf "/mnt/${RELEASE}" ; do sleep 5; done;

# Allow non-root user to access image.
chmod 666 "debian.img" "debian.id_rsa" "debian.id_rsa.pub"
