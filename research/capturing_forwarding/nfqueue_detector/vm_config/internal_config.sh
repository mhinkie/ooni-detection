#internal interface configuration
#the interface resides in an internal network with the only other host being the ooniprobe
ip link set enp0s8 up
ip addr add 192.168.100.20/24 dev enp0s8
#allow jumbo frames
ifconfig enp0s8 mtu 9000
