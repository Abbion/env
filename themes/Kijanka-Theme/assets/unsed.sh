#!/bin/sh
sed -i \
         -e 's/rgb(0%,0%,0%)/#3d404d/g' \
         -e 's/rgb(100%,100%,100%)/#ffffff/g' \
    -e 's/rgb(50%,0%,0%)/#3d404d/g' \
     -e 's/rgb(0%,50%,0%)/#6cb88c/g' \
 -e 's/rgb(0%,50.196078%,0%)/#6cb88c/g' \
     -e 's/rgb(50%,0%,50%)/#3d404d/g' \
 -e 's/rgb(50.196078%,0%,50.196078%)/#3d404d/g' \
     -e 's/rgb(0%,0%,50%)/#ffffff/g' \
	"$@"
