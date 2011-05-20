#!/bin/bash
cd clang_src
svn revert `svn status -q | awk '{print $2}'`
cd tools/clang
svn revert `svn status -q | awk '{print $2}'`
