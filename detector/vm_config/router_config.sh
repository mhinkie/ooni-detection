#Configurates the vm as router with nat
#Interface facing the internet
EXTERNAL_IF=enp0s3
#interface facing the local network
INTERNAL_IF=enp0s8

# activate routing
echo "1" > /proc/sys/net/ipv4/ip_forward
# everyting coming from inside and waiting to be forwarded is sent to the detector (using nfqueue)
iptables -A FORWARD -i ${INTERNAL_IF} -j NFQUEUE --queue-num 0

# add default gateway
route add default gw 192.168.56.1 ${EXTERNAL_IF}
