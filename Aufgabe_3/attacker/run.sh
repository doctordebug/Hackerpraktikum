#!/bin/sh

export ATK_SERVER_IP="$1"
export VLN_SERVER_IP="$2"
export VLN_DNS_PORT_IN="$3"
export VLN_DNS_PORT_OUT="$4"

# Keep script running in background with nohup
nohup python3 /vagrant/dns.py &

