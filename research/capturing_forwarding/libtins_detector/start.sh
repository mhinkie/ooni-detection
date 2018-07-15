#!/bin/sh

git pull
cd build

cmake ../
make
./det ../detector.cfg
