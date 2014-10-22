#!/bin/bash

sudo apt-get install python-pip
sudo pip install virtualenv

virtualenv --no-site-packages sandbox
source ./sandbox/bin/activate
easy_install buildbot

buildbot create-master master
buildbot start master

deactivate
