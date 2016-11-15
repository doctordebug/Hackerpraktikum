import datetime
from collections import Counter

from utils import log
from wep.iv_and_cipher_generator import iv_and_stream_key_generator


def get_most_common_byte(data, n=256):
    # Originally used in computing the first bytes of the main key.
    # Not needed because we already know the iv
    t_set = []
    for pair in data:
        x_i = pair.get('stream_key')[0]
        # TODO: Zahlenraum anpassen
        t_i = (1 - x_i) % n
        t_set.append(t_i)
    return Counter(t_set).most_common(1)[0]


def calculate_first_key_byte(t, n):
    # Average case t = K[0] + K[1] + 1
    for i in range(n):
        k_0 = i
        k_1 = t - k_0 - 1
        yield k_1


def simulate_permutation(part_of_key):
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
    for i in range(len(part_of_key)):
        j = (j + s[i] + part_of_key[i]) % n
        s[i], s[j] = s[j], s[i]
    return s, i, j


def calculate_key_byte(key_stream, s_box, i, j, n):
    """
    Approximate the key byte at position i
    :param key_stream: RC4 key stream
    :param s_box: S-box at step i-1
    :param i: iterator
    :param j: iterator at step i-1
    :return: key byte at position i
    """
    key_byte = (s_box[(i - key_stream[i - 1]) % n] - (j + s_box[i])) % n
    return key_byte


if __name__ == '__main__':
    start = datetime.datetime.now()
    n = 256
    tuple_amount = 100000
    key_length = 40
    # Retrieve sample set of bytearray tuples
    log("Collection Key Stream ... ",level=0)
    stream_key, main_key = iv_and_stream_key_generator(tuple_amount=tuple_amount, n=n, cache=True)
    log("Key Stream collected after {}ms".format(int((datetime.datetime.now() - start).total_seconds() * 1000)),level=0)

    log("First bytes: {} {} {}".format(main_key[0], main_key[1], main_key[2]), level=0)
    log("Start Hacking {}ms".format(int((datetime.datetime.now() - start).total_seconds() * 1000)),level=0)
    candidate_byte = bytes()
    possible_key = bytearray()
    compound_key = bytearray()
    for r in range(key_length):
        candidates = []
        for tuple in stream_key:
            compound_key = tuple.get('iv')
            if candidate_byte:
                compound_key += bytes([candidate_byte])
            # Internal permutation S_(i-1) and index j at (i-1)th step
            s_box, i, j = simulate_permutation(compound_key)
            # Calculate possible key byte K[i]
            candidates.append(calculate_key_byte(tuple.get('stream_key'), s_box, i + 1, j, n))
        candidate_byte = Counter(candidates).most_common(1)[0][0]
        possible_key += bytes([candidate_byte])

    ms_end = int((datetime.datetime.now() - start).total_seconds() * 1000)
    s_end = int((datetime.datetime.now() - start).total_seconds())
    log("Key found after {}ms ({}seconds)".format(ms_end,s_end),level=0)
    print(possible_key)
    print(main_key)
