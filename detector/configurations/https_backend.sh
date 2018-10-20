#!/bin/sh

QUEUE_NUM=0
QUEUE_NAME=https_backend

# first param = queue num
if [ -n "$1" ]; then
  QUEUE_NUM=$1
fi

echo "https-backend setup"

# check all dns replies
iptables -A ${QUEUE_NAME} -p udp --sport 53 -j NFQUEUE --queue-num ${QUEUE_NUM}

# check all outgoing tls
iptables -A ${QUEUE_NAME} -p tcp --dport 443 -j NFQUEUE --queue-num ${QUEUE_NUM}
