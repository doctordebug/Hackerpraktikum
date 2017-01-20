#!/bin/bash
# From http://www.linuxfromscratch.org/blfs/view/6.2.0/server/bind.html
# Should be vulnerable according to https://kb.isc.org/article/AA-00924/0/CVE-2008-1447%3A-DNS-Cache-Poisoning-Issue-Kaminsky-bug.html
cd ~

# Download bind and boot script
wget -O bind-9.3.3.tar.gz --progress=bar:force "ftp://ftp.isc.org/isc/bind9/9.3.3/bind-9.3.3.tar.gz"
tar -xvf bind-9.3.3.tar.gz
cd bind-9.3.3

# Make
sed -i 's/#ifdef SO_BSDCOMPAT/#if 0/' lib/isc/unix/socket.c && ./configure --prefix=/usr --sysconfdir=/etc --enable-threads --with-libtool && make

# Install
make install SHELL=/bin/bash
eval "chmod 755 /usr/lib/{lib{bind9,isc{,cc,cfg},lwres,dns}.so.*.?.?}"

# Install documentation
cd doc
eval "install -v -d -m755 /usr/share/doc/bind-9.3.3/{arm,draft,misc,rfc}"
install -v -m644 arm/*.html /usr/share/doc/bind-9.3.3/arm
install -v -m644 draft/*.txt /usr/share/doc/bind-9.3.3/draft
install -v -m644 rfc/* /usr/share/doc/bind-9.3.3/rfc 
eval "install -v -m644 misc/{dnssec,ipv6,migrat*,options,rfc-compliance,roadmap,sdb} /usr/share/doc/bind-9.3.3/misc"

# Add user named for jailing purposes
groupadd -o -g 20 named && useradd -c "BIND Owner" -g named -s /bin/false -u 20 named
install -d -m770 -o named -g named /srv/named

cd /srv/named
mkdir -p dev etc/namedb/slave var/run
mknod /srv/named/dev/null c 1 3
mknod /srv/named/dev/random c 1 8
eval "chmod 666 /srv/named/dev/{null,random}"
mkdir /srv/named/etc/namedb/pz
cp /etc/localtime /srv/named/etc

# Generate secret for named.conf and rndc.conf
VAL=$(rndc-confgen -b 512 -r /dev/urandom | grep -m 1 "secret" | cut -d '"' -f 2)

# Configure
cp $1/named.conf /srv/named/etc/named.conf
sed -i "s@<secret>@${VAL}@g" /srv/named/etc/named.conf

cp $1/rndc.conf /etc/rndc.conf
sed -i "s@<secret>@${VAL}@g" /etc/rndc.conf

cp -rf $1/named.conf.options /srv/named/etc/named.conf.options

cp $1/127.0.0 /srv/named/etc/namedb/pz/127.0.0
cp $1/root.hints /srv/named/etc/namedb/root.hints

echo -e "search dns\nnameserver 127.0.0.1" > /etc/resolv.conf

chown -R named.named /srv/named