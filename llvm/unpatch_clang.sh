#!/bin/bash
cd clang_src
files=`(svn status -q ;cd tools/clang/ && svn status -q ) | awk '{print $2}'`
svn revert $files
