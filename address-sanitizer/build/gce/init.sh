#!/bin/bash
sudo apt-get --yes install subversion build-essential git screen buildbot-slave buildbot vim
mkdir -p bin
svn checkout http://address-sanitizer.googlecode.com/svn/trunk/build/gce scripts
scripts/install_ninja.sh
scripts/install_cmake.sh
