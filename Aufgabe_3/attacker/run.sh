#!/bin/sh

# Keep script running in background with nohup
nohup python3 /vagrant/dns.py &

sed -i '1s;^;nameserver $1\n;' /etc/resolv.conf
