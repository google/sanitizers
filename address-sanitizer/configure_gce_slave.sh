#!/bin/bash -e

echo "Installing build dependencies..."
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install -y g++ clang++ make buildbot subversion git vim zip libstdc++6:i386

echo "Getting fresh cmake..."
cd
wget http://www.cmake.org/files/v3.0/cmake-3.0.2.tar.gz
tar -xzf cmake-3.0.2.tar.gz
cd cmake-3.0.2
./configure
make -j16
sudo make install

echo "Getting fresh ninja..."
cd
git clone git://github.com/martine/ninja.git
cd ninja
git checkout release
./bootstrap.py
sudo install ninja /usr/bin/ -o root -g root

echo "Setting up external disk at /dev/sdb..."
sudo mkdir -p /mnt/b/
sudo /usr/share/google/safe_format_and_mount -m "mkfs.ext4 -F" /dev/sdb /mnt/b
sudo chown buildbot:buildbot /mnt/b
uuid=$(sudo blkid -o value -s UUID /dev/sdb)
if ! grep ${uuid} /etc/fstab
then
  sudo sh -c "echo UUID=${uuid} /mnt/b/ ext4 defaults 1 1 >> /etc/fstab"
fi

echo "Setting up buildbot..."
read -p "Enter slave name: " -e slave_name
read -p "Enter password: " -e slave_password
echo "Master:"
select master in llvm glibc;
do
  case $master in
    "llvm")
      master_address="lab.llvm.org:9990"
      break
      ;;
    "glibc")
      master_address="130.211.48.148:9991"
      break
      ;;
  esac
done
cd /mnt/b/
sudo sudo -u buildbot buildslave create-slave ${slave_name} ${master_address} ${slave_name} "${slave_password}"
sudo sudo -u buildbot sed -i "s/keepalive = [0-9]\+/keepalive = 200/" ${slave_name}/buildbot.tac

sudo vim ${slave_name}/info/admin

gpp_version=$(g++ --version | sed -n "s/.*g++ (Debian \(.\+\)).*/\1/p")
binutils_version=$(dpkg -s binutils | sed -n "s/.*Version: \([^$]\+\).*/\1/p")
cmake_version=$(cmake --version | sed -n "s/.*cmake version \([^$]\+\).*/\1/p")
sudo sh -c "cat > ${slave_name}/info/host << EOF
Debian GNU/Linux 7.7 (wheezy)
$(uname -srv)
n1-highcpu-16 GCE instance (16 vCPU, 14.4 GB memory)

g++ ${gpp_version}
binutils ${binutils_version}
cmake ${cmake_version}
"
sudo vim ${slave_name}/info/host

sudo sh -c "cat > /etc/default/buildslave << EOF
SLAVE_ENABLED[1]=1                    # 1-enabled, 0-disabled
SLAVE_NAME[1]=\"${slave_name}\"   # short name printed on start/stop
SLAVE_USER[1]=\"buildbot\"              # user to run slave as
SLAVE_BASEDIR[1]=\"/mnt/b/${slave_name}\"                   # basedir to slave (absolute path)
SLAVE_OPTIONS[1]=\"\"                   # buildbot options
SLAVE_PREFIXCMD[1]=\"\"                 # prefix command, i.e. nice, linux32, dchroot
"

echo "DONE!"
echo
echo "If you need Android SDK/NDK, please install them manually."
echo "To start the slave, run: buildslave start /mnt/b/${slave_name}/"
