#!/bin/sh

# Set vulnerable dns
sed -i '1s;^;nameserver 127.0.0.1\n;' /etc/resolv.conf

# Start bind
/usr/sbin/named -u named -t /srv/named -c /etc/named.conf

# Vagrant specific configuration
# Change routing of traffic to the bridged interface (eth1)
# If this is not done DNS responses will arrive on interface eth0
ip route change default dev eth1 via $1