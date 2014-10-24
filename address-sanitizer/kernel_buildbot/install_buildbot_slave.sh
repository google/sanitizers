#!/bin/bash

sudo apt-get install python-pip
sudo pip install virtualenv

virtualenv --no-site-packages sandbox
source ./sandbox/bin/activate
easy_install buildbot-slave

master_host_port=dmitryc-z620.msk:9990

buildslave create-slave slave $master_host_port kasan-slave kasan
buildslave start slave

deactivate
