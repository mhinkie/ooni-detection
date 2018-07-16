#!/bin/sh
#script to start the router on the ooni-detector

echo "Killing old detectors"
killall det
echo
echo



echo "Building..."
cd /home/oonid/deploy/libtins_detector/build
rm -rf *
# build
cmake ../
make

echo
echo
echo "Configuring interfaces..."
#configure interfaces
../vm_config/internal_config.sh
../vm_config/external_config.sh

echo
echo
echo "Starting detector..."
# run
./det ../detector.cfg
