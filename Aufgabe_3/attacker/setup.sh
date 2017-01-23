#!/bin/sh

apt-get install -y dnsutils python3 python3-pip libpcap-dev tcpreplay
pip3 install scapy-python3

echo "ATK_SERVER_IP=$1" >> /etc/environment
echo "VLN_SERVER_IP=$2" >> /etc/environment
echo "VLN_DNS_PORT_IN=$3" >> /etc/environment
echo "VLN_DNS_PORT_OUT=$4" >> /etc/environment
