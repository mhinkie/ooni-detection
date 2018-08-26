#!/bin/sh



echo "Whatsapp iptables setup"

iptables --flush

# put dns requests in queue for detection purposes
iptables -A FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0
echo
echo
