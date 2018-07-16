#https://serverfault.com/questions/497438/how-to-reset-ubuntu-12-04-iptables-to-default-without-locking-oneself-out

iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
