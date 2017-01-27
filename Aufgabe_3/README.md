# Aufgabe 1
Umsetzung eines einfachen DNS-Servers

# Aufgabe 2
Exploit für das gegebene Netzwerk-Setup (Cache Poisoning nach Kaminsky)

# Aufgabe 3
Ausarbeitung

---
# Vagrant README

## Preparation
Install [Virtualbox](https://www.virtualbox.org/wiki/Downloads) and [Vagrant](https://www.vagrantup.com/downloads.html).
Set the INTERFACE variable in the Vagrantfile according to the interface of your host machine and the HOST_NETWORK_GATEWAY variable to the gateway ip address.
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

	rndc <command>

Tshark is installed to monitor network traffic:

    tshark -i eth1 port 53 and port 54
    tshark -i eth1 -T fields -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e dns.id -e dns.qry.name -R "ip.addr == 216.69.185.38 and dns.count.answers == 1"


### Attacker
VM containing the cache poisoning script and the malicious DNS server (default: 192.168.0.26).

To access the scripts, log in to the VM and navigate to the "/vagrant" folder.
Start the malicious dns server (should be already running):

    nohup python3 dns.py &

Start the poison script:

    python3 poison.py
