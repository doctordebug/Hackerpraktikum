## Preparation
Install [Virtualbox](https://www.virtualbox.org/wiki/Downloads) and [Vagrant](https://www.vagrantup.com/downloads.html).
Set the INTERFACE variable in the Vagrantfile according to the interface of your host machine and the HOST_NETWORK_GATEWAY variable to the gateway ip address.
If you are not using the 192.168.0.0/24 subnet you have to change VLN_IP and ATK_IP accordingly.

Make sure that the line endings of the files in the bind directory are Unix style line endings (\n).
To fix the line endings use:
	sed -i 's/\r//g' Vagrantfile
	sed -i 's/\r//g' vulnerable/*
	sed -i 's/\r//g' vulnerable/bind/*
	sed -i 's/\r//g' attacker/*

## Setup
Navigate into the folder that holds the Vagrantfile and execute the following from the console.

    vagrant up
Press enter and grab a drink, this will take a few minutes.
## Access to VMs
### vagrant
    vagrant ssh <vulnerable/attacker>

### SSH
username: vagrant
password: vagrant

## Further information
The folders "vulnerable" and "attacker" are shared folders that are mapped to the "/vagrant" folder inside the guest. 
### Vulnerable
Bind-9.3.3 is used as it should be vulnerable to the Kaminsky DNS cache poisoning attack [(source)](https://kb.isc.org/article/AA-00924/0/CVE-2008-1447%3A-DNS-Cache-Poisoning-Issue-Kaminsky-bug.html).
The DNS server is listening on the IP and port configured in the Vagrantfile (default: 192.168.0.25, port 53 for incoming and port 54 for outgoing queries).

Start the named daemon (should be already running):

    /usr/sbin/named -u named -t /srv/named -c /etc/named.conf

Configuration reload, cache flush and more commands to control the daemon are available via the rndc interface:

	rndc <reload/flush/...>

Tshark is installed to monitor network traffic, some useful commands are:

    tshark -i eth1 port 53 and port 54
    tshark -i eth1 -T fields -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e dns.id -e dns.qry.name -R "ip.addr == 216.69.185.38 and dns.count.answers == 1"
    tshark -i eth0 -Y "udp.dstport == 53 and ip.src == 192.168.0.11" -T text -V

Log to statistics file:

    rndc stats

##### Gather information about resolved queries:



First set Bind9 debug level, see [this](http://docstore.mik.ua/orelly/networking_2ndEd/dns/ch13_01.htm) for additional information regarding debugging levels.

    rndc trace 90

Inspect the Log file created from the resolver category (*), found in: 

    /srv/named/var/log/named/resolver.log
    

### Attacker
VM containing the cache poisoning script and the malicious DNS server (default: 192.168.0.26). To access the scripts, log in to the VM and navigate to the "/vagrant" folder.

Start the malicious dns server (should be already running):

    nohup python3 dns.py &

Start the poison script (*):

    python3 poison.py


(*) Dont forget to switch to root (sudo su)
