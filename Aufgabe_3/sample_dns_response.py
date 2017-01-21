from scapy.all import *
answer = sr1(IP(dst="192.168.0.23")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="www.lukasjung.de")),verbose=0)
print(answer[DNS].summary())
