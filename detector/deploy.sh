#!/bin/bash
#script to deploy the detector on ooni-detector vm

#for this script, root login has to be enabled on ooni-detector-vm

TEST_NAME=whatsapp
#can be mobile or deskop
TEST_SETUP=mobile

if [ -n "$1" ]; then
  TEST_NAME=$1
fi

if [ "$1" == "none" ]; then
  TEST_NAME=""
fi

echo "Deploying ${TEST_NAME}"

VM_IP=192.168.56.101
VM_USER=oonid
DEPLOY_PATH=deploy/nfqueue_detector
OONID_HOME=/home/oonid/

#compile
echo "compiling"
cd build
if ! cmake ../; then
  echo "cmake error!"
  exit 1
fi
if ! make; then
  echo "error compiling/linking!"
  exit 1
fi
cd ..
echo
echo



echo "running startscript"
if [ "$TEST_SETUP" == "mobile" ]; then
  #test setup on host with ap - probe is a mobile client
  ./start_local.sh $TEST_NAME
else
  #test setup on vm (probe is a vm)
  #delete everything as root (because build dir is filled with root)
  ssh root@${VM_IP} "cd ${OONID_HOME}${DEPLOY_PATH}; rm -rf *"
  echo "copying files"
  rsync -av -e ssh --exclude='doc/*' ./ ${VM_USER}@${VM_IP}:${DEPLOY_PATH}
  echo
  echo

  #https://stackoverflow.com/questions/305035/how-to-use-ssh-to-run-a-shell-script-on-a-remote-machine
  ssh root@${VM_IP} "bash -s" < start_on_oonid.sh $TEST_NAME  #> output.txt
fi
