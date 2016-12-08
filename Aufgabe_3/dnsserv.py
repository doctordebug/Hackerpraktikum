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
#        assert dns.opcode == 0, dns.opcode  # QUERY
#        assert dnsqtypes[dns[DNSQR].qtype] == 'A', dns[DNSQR].qtype
        query = dns[DNSQR].qname.decode('ascii') 
#        head, domain, tld, tail = query.rsplit('.', 3)

#        print("__________________________________________")
#        dns.show()
#        print("__________________________________________")

#        assert head == 'www' and domain == 'bank' and tld == 'com' and tail == ''

        if dnsqtypes[dns[DNSQR].qtype] == 'A':
            rdata="12.34.56.78"

            response = DNS(
                id=dns.id, ancount=1, qr=1, aa=0, ra=0, rd=0,
                qdcount=1,
                qd=dns.qd,
                an=DNSRR(rrname=str(query), type='A', rdata=rdata, ttl=1234))
        if dnsqtypes[dns[DNSQR].qtype] == 'MX':
            dns.show()
            rdata=query

            response = DNS(
                id=dns.id, ancount=1, qr=1, aa=0, ra=0, rd=0,
                nscount=dns.nscount,
                ns=dns.ns,
                arcount=dns.arcount,
                ar=dns.ar,
                qdcount=dns.qdcount,
                qd=dns.qd,
                an=DNSRR(rrname=str(query), type='MX', rdata=rdata, ttl=1234))
        else:
            response = DNS(id=dns.id, ancount=0, rcode=3, aa=1, ra=0, rd=0,
                nscount=dns.nscount,
                ns=dns.ns,
                arcount=dns.arcount,
                ar=dns.ar,
                qdcount=dns.qdcount,
                qd=dns.qd)
			#            print(dnsqtypes[dns[DNSQR].qtype])

#        print("__________________________________________")
#        response.show()
#        print("__________________________________________")

#        print(repr(response))
        sock.sendto(bytes(response), addr)

    except Exception as e:
        print('')
        print_exc()
        print('garbage from {!r}? data {!r}'.format(addr, request))
