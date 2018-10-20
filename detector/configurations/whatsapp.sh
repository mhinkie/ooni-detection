#!/bin/sh

QUEUE_NUM=0
QUEUE_NAME=whatsapp

# first param = queue num
if [ -n "$1" ]; then
  QUEUE_NUM=$1
fi

echo "Whatsapp iptables setup"



# inspect all tcp (the detector contains a dynamic blocklist)
iptables -A ${QUEUE_NAME} -p tcp --sport 5222 -j NFQUEUE --queue-num ${QUEUE_NUM}
iptables -A ${QUEUE_NAME} -p tcp --sport 80 -j NFQUEUE --queue-num ${QUEUE_NUM}
iptables -A ${QUEUE_NAME} -p tcp --sport 443 -j NFQUEUE --queue-num ${QUEUE_NUM}

# inspect dns replys for whatsapp addresses
iptables -A ${QUEUE_NAME} -p udp --sport 53 -j NFQUEUE --queue-num ${QUEUE_NUM}

# put dns requests in queue for detection purposes
iptables -A ${QUEUE_NAME} -p udp --dport 53 -j NFQUEUE --queue-num ${QUEUE_NUM}
echo
echo
