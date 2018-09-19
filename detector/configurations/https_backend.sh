#!/bin/sh


echo "https-backend setup"

iptables --flush

# check all dns replies
iptables -A FORWARD -p udp --sport 53 -j NFQUEUE --queue-num 0

# check all outgoing tls
iptables -A FORWARD -p tcp --dport 443 -j NFQUEUE --queue-num 0
