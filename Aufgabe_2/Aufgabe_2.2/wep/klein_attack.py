from collections import Counter

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

    j = 0
    i = 0
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
    n = 256
    tuple_amount = 50000
    # Retrieve sample set of bytearray tuples
    stream_key, main_key = iv_and_stream_key_generator(tuple_amount=tuple_amount, n=n)

    candidates = []
    for tuple in stream_key:
        # Internal permutation S_(i-1) and index j at (i-1)th step
        s_box, i, j = simulate_permutation(tuple.get('iv'))
        # Calculate possible key byte K[i]
        candidates.append(calculate_key_byte(tuple.get('stream_key'), s_box, i, j, n))
    print(Counter(candidates).most_common(3))


    # j_1 = stream_key[0].get('iv')[-1]
    # i_1 = stream_key[0].get('iv')[-2]
    # print("K[b-2]=" + hex(j_1))
    # print("K[b-1]=" + hex(i_1))
    # print("S[b]=" + hex(s_box[len(stream_key[0].get('iv'))]))
    # fick = ((j_1 + i_1 - s_box[len(stream_key[0].get('iv')) - 1]) % 256)
    # print("K[b]= K[b-2] + K[b-1] - S[b] ")
    # print("K[b] tatsächlich :=" + str(main_key[0]))
    # print("K[b] berechnet:=" + str(fick))
