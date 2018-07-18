#!/bin/bash
#script to configure and start detector
FRULES=/etc/suricata/rules/suri.rules

killall /usr/bin/suricata
killall /usr/bin/tail

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
# takes every file in rules/ and adds them to suri.rules
echo "" > ${FRULES}
for rules_file in rules/*.rules; do
  cat ${rules_file} >> ${FRULES}
done

echo
echo
echo "starting suricata..."
tail -f /var/log/suricata/fast.log &
suricata -v -c /etc/suricata/suricata.yaml -i enp0s8 --init-errors-fatal
