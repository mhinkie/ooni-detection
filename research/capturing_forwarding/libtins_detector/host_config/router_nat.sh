#Configurates the host as a router with nat
#assumes default gw is already set

#Interface facing the internet
EXTERNAL_IF=wlx2824ff1a05f9
#interface facing the vms
INTERNAL_IF=vboxnet0


echo "1" > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o ${EXTERNAL_IF} -j MASQUERADE
iptables -A FORWARD -i ${INTERNAL_IF} -j ACCEPT
