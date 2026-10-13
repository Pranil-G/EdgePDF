#!/bin/bash
# $1 = file, rest = line numbers
f=$1; shift
for L in "$@"; do
  e=$(sed -n "1,${L}p" "$f" | grep "^ \* entry: " | tail -1 | awk '{print $3}')
  echo "line $L -> FUN_$e"
done
