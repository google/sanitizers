#!/bin/bash -eux
#
# Creates and configures a minimal Debian image for running HWASan tests in
# QEMU with the run_in_qemu_with_lam.sh script in this directory.
#
# Usage: sudo ./create_qemu_image.sh
#
# Outputs: the QEMU image and SSH keys in the current directory.

if [[ -f /etc/lsb-release ]] ; then 
  . /etc/lsb-release
  RELEASE=${DISTRIB_CODENAME}
fi

if [[ -f /etc/os-release ]] ; then 
  . /etc/os-release
  RELEASE=${VERSION_CODENAME}
fi

# Comma-separated list of packages.
: ${PREINSTALL_PKGS:="openssh-server,nfs-common"}

readonly DIR="$(mktemp -d)"
readonly IMAGE_DIR="${DIR}/${RELEASE}"

# Generate base system.
mkdir "${IMAGE_DIR}"
debootstrap --include="${PREINSTALL_PKGS}" "${RELEASE}" "${IMAGE_DIR}"

# Configure system to boot properly.
sed -i "/^root/ { s/:x:/::/ }" "${IMAGE_DIR}/etc/passwd"
echo "T0:23:respawn:/sbin/getty -L ttyS0 115200 vt100" \
  >> "${IMAGE_DIR}/etc/inittab"

# debian
[[ -d ${IMAGE_DIR}/etc/network ]] && cat <<EOF >${IMAGE_DIR}/etc/network/interfaces
auto eth0
iface eth0 inet dhcp
EOF

# ubuntu
[[ -d ${IMAGE_DIR}/etc/netplan ]] && cat <<EOF >${IMAGE_DIR}/etc/netplan/config.yaml
network:
    version: 2
    renderer: networkd
    ethernets:
        eth0:
            dhcp4: true
EOF

echo "/dev/root / ext4 defaults 0 0" >> "${IMAGE_DIR}/etc/fstab"
echo -en "127.0.0.1\tlocalhost\n" > "${IMAGE_DIR}/etc/hosts"
echo "nameserver 8.8.8.8" >> "${IMAGE_DIR}/etc/resolve.conf"
echo "debian" > "${IMAGE_DIR}/etc/hostname"

# Set up SSH.
ssh-keygen -q -f "debian.id_rsa" -t rsa -N ""
mkdir -p "${IMAGE_DIR}/root/.ssh/"
cat "debian.id_rsa.pub" > "${IMAGE_DIR}/root/.ssh/authorized_keys"
echo "MaxSessions 1000" >>${IMAGE_DIR}/etc/ssh/sshd_config

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
chmod 666 "debian.img"
