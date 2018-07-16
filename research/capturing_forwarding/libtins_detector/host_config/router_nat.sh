#Configurates the host as a router with nat
#assumes default gw is already set

#Interface facing the internet
EXTERNAL_IF=wlx2824ff1a05f9
#interface facing the vms
INTERNAL_IF=vboxnet0

# network information of internal vm network (for routing configuration)
VM_INTERNAL_NETWORK=192.168.100.0
VM_INTERNAL_NETMASK=255.255.255.0
#inteface on ooni detector facing the host
OONI_DETECTOR_IP=192.168.56.101

# activate nat
echo "1" > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o ${EXTERNAL_IF} -j MASQUERADE
iptables -A FORWARD -i ${INTERNAL_IF} -j ACCEPT

# add route to internal vm network
route add -net ${VM_INTERNAL_NETWORK} netmask ${VM_INTERNAL_NETMASK} gw ${OONI_DETECTOR_IP}
