#!/bin/bash
for fff in *.dot; do
  dot -Tpng $fff > `basename $fff .dot`.png &
done
wait
