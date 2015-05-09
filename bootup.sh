#sudo `echo 0 > /proc/sys/net/ipv4/ip_forward`
sudo sysctl net.ipv4.ip_forward=0
sudo ifconfig eth0 promisc
sudo ifconfig eth2 promisc
sudo ./a.out eth1
