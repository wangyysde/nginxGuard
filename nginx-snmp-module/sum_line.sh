#!/bin/bash
num=0
for f in `ls ./` 
do
  if [ -f $f ]
  then 
     n=`cat ${f} | wc -l`
     num=$[${num}+${n}]
  fi
done
echo ${num}
