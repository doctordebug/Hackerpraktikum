#!/bin/sh

BASE_DIR=/vagrant

# Install vulnerable bind version
bash $BASE_DIR/bind/bind-9.3.3.bash $BASE_DIR/bind $1 $2 $3

apt-get install -y tshark