#!/bin/bash
#script to configure and start detector
#requires libnfnetlink libmnl and libnetfilter_queue

echo "Killing old detectors"
killall det
echo
echo

cd /home/oonid/deploy/nfqueue_detector/

echo "Configuring interfaces..."
#configure interfaces
vm_config/reset_config.sh
vm_config/internal_config.sh
vm_config/external_config.sh
vm_config/router_config.sh

echo
echo
echo "Starting detector..."
cd build
./det 0
