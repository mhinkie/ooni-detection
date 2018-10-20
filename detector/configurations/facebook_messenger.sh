#!/bin/sh

QUEUE_NUM=0
QUEUE_NAME=facebook_messenger

# first param = queue num
if [ -n "$1" ]; then
  QUEUE_NUM=$1
fi

echo "Facebook iptables setup"

# packets coming FROM an ip in facebook's AS will be given to the queue
# all other packets are routed without inspection
# facebook address space: https://stackoverflow.com/questions/11164672/list-of-ip-space-used-by-facebook
for src_addr in `whois -h whois.radb.net '!gAS32934' | grep /`
do
  iptables -A ${QUEUE_NAME} -s $src_addr -j NFQUEUE --queue-num ${QUEUE_NUM}
done

# put dns requests in queue for detection purposes
iptables -A ${QUEUE_NAME} -p udp --dport 53 -j NFQUEUE --queue-num ${QUEUE_NUM}

echo
echo
#echo "Rules: "
#iptables -L
