#!/bin/bash
#script to deploy the detector on ooni-detector vm

#for this script, root login has to be enabled on ooni-detector-vm

VM_IP=192.168.56.101
VM_USER=oonid
DEPLOY_PATH=deploy/libtins_detector

scp -r * ${VM_USER}@${VM_IP}:${DEPLOY_PATH}

#https://stackoverflow.com/questions/305035/how-to-use-ssh-to-run-a-shell-script-on-a-remote-machine
ssh root@${VM_IP} "bash -s" < start_on_oonid.sh
