#!/bin/sh


echo "Facebook iptables setup"

iptables --flush

# packets coming FROM an ip in facebook's AS will be given to the queue
# all other packets are routed without inspection
# facebook address space: https://stackoverflow.com/questions/11164672/list-of-ip-space-used-by-facebook
for src_addr in `whois -h whois.radb.net '!gAS32934' | grep /`
do
  iptables -A FORWARD -s $src_addr -j NFQUEUE --queue-num 0
done

echo
echo
#echo "Rules: "
#iptables -L
