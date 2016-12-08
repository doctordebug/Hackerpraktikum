# Use scapy2.3.1+ from pip (secdev original) or for Python3 use the
# https://github.com/phaethon/scapy Scapy3K version.
# Using pip3: pip3 install scapy-python3
#
# Example DNS server that resolves NAME.IPV4.example.com A record
# requests to an A:IPV4 response.
#
# $ dig test.12.34.56.78.example.com -p 1053 @127.0.0.1 +short
# 12.34.56.78

from scapy.all import DNS, DNSQR, DNSRR, dnsqtypes
from socket import AF_INET, SOCK_DGRAM, socket
from traceback import print_exc

sock = socket(AF_INET, SOCK_DGRAM)
sock.bind(('0.0.0.0', 1053))

while True:
    request, addr = sock.recvfrom(4096)

    try:
        dns = DNS(request)
        query = dns[DNSQR].qname.decode('ascii') 

        if dnsqtypes[dns[DNSQR].qtype] == 'A':
            rdata="12.34.56.78"

            response = DNS(
                id=dns.id, ancount=1, qr=1, aa=0, ra=0, rd=0,
                qdcount=1,
                qd=dns.qd,
                an=DNSRR(rrname=str(query), type='A', rdata=rdata, ttl=1234))
        elif dnsqtypes[dns[DNSQR].qtype] == 'AAAA':
            response = DNS(
                id=dns.id, ancount=0, qr=1, aa=1, ra=0, rd=0,
                qdcount=dns.qdcount,
                qd=dns.qd)
            #        elif dnsqtypes[dns[DNSQR].qtype] == 'MX':
            #            response = DNS(
            #                id=dns.id, arcount=1, qr=1, aa=0, ra=0, rd=0,
            #                nscount=dns.nscount,
            #                ns=dns.ns,
            #                qdcount=dns.qdcount,
            #                qd=dns.qd,
            #                ar=DNSRR(rrname=str(query), type='OPT', rdata='.', ttl=1234))
        else:
            response = DNS(id=dns.id, ancount=0, rcode=3, aa=1, ra=0, rd=0,
                nscount=dns.nscount,
                ns=dns.ns,
                arcount=dns.arcount,
                ar=dns.ar,
                qdcount=dns.qdcount,
                qd=dns.qd)
            print(dnsqtypes[dns[DNSQR].qtype])

        sock.sendto(bytes(response), addr)

    except Exception as e:
        print('')
        print_exc()
        print('garbage from {!r}? data {!r}'.format(addr, request))
