#Configurates the host as a router with nat
#assumes default gw is already set

#Interface facing the internet
EXTERNAL_IF=wlx2824ff1a05f9
#interface facing the vms
INTERNAL_IF=enp3s0

ifconfig ${INTERNAL_IF} 192.168.44.1 netmask 255.255.255.0 up
#start dhcp server for easier configuration of ap
service isc-dhcp-server start
#service isc-dhcp-server status

# network information of internal vm network (for routing configuration)
INTERNAL_NETWORK=192.168.44.0
INTERNAL_NETMASK=255.255.255.0
#ooni detector is running locally

# activate nat
echo "1" > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o ${EXTERNAL_IF} -j MASQUERADE
iptables -A FORWARD -i ${INTERNAL_IF} -j ACCEPT

# add route to internal vm network
# as all host lie in the connected network, no route is necessary
