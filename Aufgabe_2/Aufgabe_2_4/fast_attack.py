from collections import Counter
from itertools import product

from Aufgabe_2.utils import log, log_timing
from rc4.rc4 import fixed_rc4
from wep.iv_and_cipher_generator import iv_and_stream_key_generator


def simulate_permutation(iv, n=256):
    """
    Approximate the permutation by simulating the first i steps
    of the key scheduling of RC4
    :param iv: Known part of the main key
    :return: s: S-box permuted to step 3, j: index j at step 3, s_invert: inverted s-box at step 3
    """
    # Initialize s-box
    s = []
    for i in range(n):
        s.append(i)
    s_invert = list(s)

    j = 0
    # Calculate permutation for bytes K[0] to K[2]
    for i in range(3):
        j = (j + s[i] + iv[i]) % n
        s[i], s[j] = s[j], s[i]

    # Invert s-box at step 3
    for r in range(len(s)):
        s_invert[s[r]] = r

    return s, j, s_invert


def calculate_key_byte_vote(i, key_stream, s_box_3, s_box_3_invert, j_3, n=256):
    """
    Approximate the key byte at position i
    :param key_stream: RC4 key stream
    :param s_box_3: S-box at step i-1
    :param i: iterator
    :param j: iterator at step i-1
    :return: key byte at position i
    """
    # Calculate key byte
    sum = s_box_3[3]
    for l in range(4, i + 4):
        sum = (sum + s_box_3[l]) % n
    key_byte = (s_box_3_invert[((3 + i) - key_stream[2 + i]) % n] - (j_3 + sum) % n) % n
    return key_byte


def vote_generator(iv, key_stream, key_length):
    s_box_3, j_3, s_box_3_invert = simulate_permutation(iv)
    key = []
    for i in range(key_length):
        key.append(calculate_key_byte_vote(i, key_stream, s_box_3, s_box_3_invert, j_3))
    return key


@log_timing()
def test_keys(key_set_iterator, tuple, n=256):
    iv = tuple[0]
    stream = tuple[1]
    for key_set in key_set_iterator:
        log("Got some keys: {}".format(key_set), level=1)
        for key in key_set:
            calculated_key_bytes = [key[0][0]]
            for i in range(1, len(key)):
                calculated_key_bytes.append((key[i][0] - key[i - 1][0]) % n)
            main_key = bytearray(calculated_key_bytes)
            calculated_stream = fixed_rc4(iv + main_key, cipher_length=len(stream))
            if calculated_stream == stream:
                log("Key found: {}".format(main_key), level=0)
                return main_key


@log_timing()
def get_key_vote_dict(key_length_bytes):
    # Initialize dict
    key = dict()
    for i in range(key_length_bytes):
        key.update({i: []})
    for tuple in iv_stream_pair:
        single_vote = vote_generator(tuple.get('iv'), tuple.get('stream_key'), key_length_bytes)
        for index, key_s in enumerate(single_vote):
            key_votes = key.get(index)
            key_votes.append(key_s)
            key.update({index: key_votes})
    return key


def combine_key_votes(key_vote_dict, tuple_amount, candidate_amount=3):
    """

    :param key_vote_dict:
    :param candidate_amount: Big values may cause high runtime
    :return:
    """
    # Create dict of lists for key positions
    most_common = dict()
    for i in range(len(key_vote_dict)):
        most_common.update({i: []})
    for t, i in key_vote_dict.items():
        bytes_at_pos_t = Counter(i).most_common(candidate_amount)
        for j in bytes_at_pos_t:
            tmp = most_common.get(t)
            p = j[1] / tuple_amount
            tmp.append((j[0], p))
            most_common.update({t: tmp})

    # Begin of combination process
    possible_key_set = []
    # Initialize with only the most common bytes
    for i in range(len(key_vote_dict)):
        key_byte_and_p = list(most_common.values())[i][0]
        possible_key_set.append([key_byte_and_p])

    while True:
        old_set = list()
        # Calculate possible key combinations
        cartesian_product_set_of_tuples = list(product(*possible_key_set))
        # Exclude already tested keys
        cartesian_product_set_of_tuples = set(cartesian_product_set_of_tuples) - set(old_set)
        # Return list of keys
        yield cartesian_product_set_of_tuples

        old_set += cartesian_product_set_of_tuples
        # calculate byte with smallest distance in probability
        candidate_list = []
        for key, value in most_common.items():
            for index, v in enumerate(value):
                if v not in possible_key_set[key]:
                    # Calculate and add probability delta
                    max_p = possible_key_set[key][0][1]
                    p = max_p - v[1]
                    c = (v[0], v[1], p)
                    candidate_list.append(c)
                    break
                # If all candidates are used, append placeholder
                if index == len(value) - 1:
                    candidate_list.append((0, 0, 1))

        # Take byte with smallest probability distance to top voted at its key byte position
        candidate = sorted(candidate_list, key=lambda x: x[2])[0]
        # Break if all candidates are used in combination process
        if candidate[2] == 1:
            log("Out of candidates.", level=0)
            return None
        # Remove probability delta
        candidate_position = candidate_list.index(candidate)
        candidate_without_delta = (candidate[0], candidate[1])
        # Append key byte to set at position
        possible_key_set[candidate_position].append(candidate_without_delta)


if __name__ == '__main__':
    key_length_bytes = 5
    tuple_amount = 35000
    print("Generating Keystream")
    # Retrieve sample set of bytearray tuples
    iv_stream_pair, main_key = iv_and_stream_key_generator(key_length=key_length_bytes, tuple_amount=tuple_amount)
    print("Start Hacking")

    key = get_key_vote_dict(key_length_bytes)
    key_set_iterator = combine_key_votes(key, tuple_amount, candidate_amount=3)

    test_keys(key_set_iterator, (iv_stream_pair[0].get('iv'), iv_stream_pair[0].get('stream_key')))
