#!/bin/bash
#script to configure and start detector

cd /home/oonid/deploy/nfqueue_detector/

echo
echo
echo "Configuring interfaces..."
#configure interfaces
vm_config/reset_config.sh
vm_config/internal_config.sh
vm_config/external_config.sh
vm_config/router_config.sh
