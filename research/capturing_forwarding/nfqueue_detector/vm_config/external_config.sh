#external interface config
#external interface is connected to a host-only adapter
#the host acts as a router + nat and has a route to the internal-vm network using this vm as gateway
ip addr add 192.168.56.101/24 dev enp0s3
echo "nameserver 8.8.8.8" | tee /etc/resolv.conf
#allow jumbo frames
ifconfig enp0s3 mtu 9000
