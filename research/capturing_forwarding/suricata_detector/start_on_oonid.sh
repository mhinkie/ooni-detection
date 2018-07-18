#!/bin/bash
#script to configure and start detector

cd /home/oonid/deploy/suricata_detector

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
echo "copying suri.rules..."
cp rules/suri.rules /etc/suricata/rules/

echo
echo
echo "starting suricata..."
suricata -c /etc/suricata/suricata.yaml -i enp0s8 --init-errors-fatal
