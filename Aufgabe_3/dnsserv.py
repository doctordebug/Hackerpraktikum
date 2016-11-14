# Use scapy2.3.1+ from pip (secdev original) or for Python3 use the
# https://github.com/phaethon/scapy Scapy3K version.
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
        assert dns.opcode == 0, dns.opcode  # QUERY
        assert dnsqtypes[dns[DNSQR].qtype] == 'A', dns[DNSQR].qtype
        query = dns[DNSQR].qname.decode('ascii') 
        head, domain, tld, tail = query.rsplit('.', 3)
        assert head == 'www' and domain == 'bank' and tld == 'com' and tail == ''

        rdata="12.34.56.78"

        response = DNS(
            id=dns.id, ancount=1, qr=1,
            an=DNSRR(rrname=str(query), type='A', rdata=rdata, ttl=1234))
        print(repr(response))
        sock.sendto(bytes(response), addr)

    except Exception as e:
        print('')
        print_exc()
        print('garbage from {!r}? data {!r}'.format(addr, request))
        sock.sendto(DNS(id=dns.id, ancount=1, qr=1, an=DNSRR(type='NXDOMAIN')), addr)
