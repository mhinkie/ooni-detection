#!/bin/sh
#script to start the router on the ooni-detector

killall det

cd /home/oonid/deploy/libtins_detector/build
rm -rf *

cmake ../
make
./det ../detector.cfg
