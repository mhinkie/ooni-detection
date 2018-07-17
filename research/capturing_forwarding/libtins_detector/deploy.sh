#!/bin/bash
#script to deploy the detector on ooni-detector vm

#for this script, root login has to be enabled on ooni-detector-vm

VM_IP=192.168.56.101
VM_USER=oonid
DEPLOY_PATH=deploy/libtins_detector
OONID_HOME=/home/oonid/

#delete everything as root (because build dir is filled with root)
ssh root@${VM_IP} "cd ${OONID_HOME}${DEPLOY_PATH}; rm -rf *"
echo "copying files"
scp -r * ${VM_USER}@${VM_IP}:${DEPLOY_PATH}
echo
echo

echo "running startscript"
#https://stackoverflow.com/questions/305035/how-to-use-ssh-to-run-a-shell-script-on-a-remote-machine
ssh root@${VM_IP} "bash -s" < start_on_oonid.sh > output.txt
