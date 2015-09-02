#!/bin/bash
#

cd /home/tiki/electron.block.io/

git pull

rm *.tmp


TFILE="./$$.tmp"
ls > $TFILE

git add .
git commit -m "auto"
git push
