#!/bin/sh

BASE_DIR=/vagrant

# Install vulnerable bind version
bash $BASE_DIR/bind/bind-9.3.3.bash $BASE_DIR/bind

# Start bind
/usr/sbin/named -u named -t /srv/named -c /etc/named.conf

# Named:
#	Start: /usr/sbin/named -u named -t /srv/named -c /etc/named.conf
#	Stop: killall named

# rndc:
#	rndc <command>
#	Reload: /usr/sbin/rndc -c /etc/rndc.conf reload
