#!/bin/sh
sed -i \
         -e 's/#3d404d/rgb(0%,0%,0%)/g' \
         -e 's/#ffffff/rgb(100%,100%,100%)/g' \
    -e 's/#3d404d/rgb(50%,0%,0%)/g' \
     -e 's/#6cb88c/rgb(0%,50%,0%)/g' \
     -e 's/#3d404d/rgb(50%,0%,50%)/g' \
     -e 's/#ffffff/rgb(0%,0%,50%)/g' \
	"$@"
