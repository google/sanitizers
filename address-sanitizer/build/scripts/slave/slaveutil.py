#!/usr/bin/python

import os
import sys
import socket

def slave_name():
    hostname = socket.gethostname()
    dirname = os.path.split(sys.argv[0])[-1]
    print hostname, dirname
    if dirname.startswith('slave'):
        dirname = dirname[5:]
        if dirname:
            hostname = hostname + '-' + dirname
    return hostname

def slave_password():
    return 'password'
