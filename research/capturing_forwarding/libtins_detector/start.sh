#!/bin/sh

git pull
cd build

cmake ../
make
sudo ./det ../detector.cfg
