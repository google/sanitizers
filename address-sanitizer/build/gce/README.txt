This directory contains files required to set up
and run LLVM build bots on Google Compute Engine (GCE)

Initialize the GCE instance:
  curl https://address-sanitizer.googlecode.com/svn/trunk/build/gce/init.sh | bash

Create a buildslave:
  NAME=sanitizer-buildbot3
  DIR=$HOME/$NAME
  buildslave create-slave $DIR lab.llvm.org:9990 $NAME PASSWORD
