import os

from rc4.key_scheduling import key_scheduling
from rc4.pseudo_random_generator import pseudo_random_generator
from rc4.rc4 import fixed_rc4
from utils import log


def iv_and_stream_key_generator(n=256, rounds=2, iv_length=24, key_length=40, tuple_amount=2000):
    """
    Method for generation of (iv, stream key) pairs as required by Exercise 2.2
    Modes:
        64-bit WEP(WEP-40): 40 bit key, 24-bit iv
        128-bit WEP(WEP-104): 104 bit key, 26-bit iv
    :param n: Base of the integer group
    :param rounds: Amount of rounds the pseudo random generator should be called
    :param iv_length: Length of the initializing vector
    :param key_length: Length of the key. Typically ranges from 5 to 64 with maximum of 256
    :param tuple_amount: Amount of iv and stream keys to be generated
    :return: A set of iv and stream key tuples and the main key
    """
    log("Proceeding with: length={}, amount={}, rounds={}, n={}".format(key_length, tuple_amount, rounds, n))

    # Generate random key
    main_key = bytearray(os.urandom(key_length))
    log("Using key: {}".format(main_key), level=0)
    log("First byte: {}".format(main_key[0]), level=0)

    iv_stream_set = []
    for i in range(tuple_amount):
        # Generate random iv
        iv = bytearray(os.urandom(iv_length))
        stream_key = fixed_rc4(iv + main_key, cipher_length=rounds * n, n=n)
        iv_stream_set.append(dict(iv=iv, stream_key=stream_key))
    return iv_stream_set, main_key


def export_sample(file_name="sample_data.txt"):
    data = iv_and_stream_key_generator()
    output = ""
    for pair in data:
        output += str(pair) + "\n"
    with open(file_name, 'w') as file:
        file.write(output)


if __name__ == '__main__':
    export_sample()
