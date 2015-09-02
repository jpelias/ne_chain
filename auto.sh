#!/bin/bash
#

cd /home/tiki/electron.block.io/

git config credential.helper store

git pull

rm *.tmp


TFILE="./$$.tmp"
ls > $TFILE

git add .
git commit -m "auto"
git push


git config credential.helper store

