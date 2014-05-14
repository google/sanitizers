#!/bin/bash
sudo apt-get --yes install subversion cmake build-essential git
mkdir -p bin
svn checkout http://address-sanitizer.googlecode.com/svn/trunk/build/gce scripts
scripts/install_ninja.sh
