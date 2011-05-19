#!/bin/bash
png=`basename $1 .dot`.png
dot -Tpng $1 > $png
qiv $png
rm -f $png
