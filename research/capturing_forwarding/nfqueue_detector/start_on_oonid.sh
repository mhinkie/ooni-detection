#!/bin/bash
#script to configure and start detector
#requires libnfnetlink libmnl and libnetfilter_queue

echo "Killing old detectors"
killall det
echo
echo

cd /home/oonid/deploy/nfqueue_detector/

echo
echo
echo "Configuring interfaces..."
#configure interfaces
vm_config/reset_config.sh
vm_config/internal_config.sh
vm_config/external_config.sh
vm_config/router_config.sh

echo
echo
echo "Building..."
mkdir -p build
cd build
rm -rf *
cmake ../
make

echo
echo
echo "Starting detector..."
./det
