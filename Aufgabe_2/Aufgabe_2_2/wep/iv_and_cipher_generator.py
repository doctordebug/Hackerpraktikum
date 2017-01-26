import os
from pathlib import Path

from Aufgabe_2.utils import log_timing, log
from Aufgabe_2.Aufgabe_2_2.rc4.rc4 import fixed_rc4


@log_timing()
def iv_and_stream_cipher_generator(n=256, rounds=2, iv_length=3, key_length=5, tuple_amount=1000, cache=False):
    """
    Method for generation of (iv, main key and stream key) pairs as required by Exercise 2.2
    Modes:
        64-bit WEP(WEP-40): 40 bit key, 24-bit iv
        128-bit WEP(WEP-104): 104 bit key, 26-bit iv
    :param n: Base of the integer group
    :param rounds: Amount of rounds the pseudo random generator should be called
    :param iv_length: Length of the initializing vector in bytes
    :param key_length: Length of the key in bytes. Typically ranges from 5 to 64 with maximum of 256
    :param tuple_amount: Amount of iv and stream keys to be generated
    :return: A set of iv and stream key tuples and the main key
    """
    key_file_name = "main_key"
    data_file_name = "stream_cipher"
    if cache:
        if all(Path(file).exists() for file in [key_file_name, data_file_name]):
            return load_cache(key_file_name, data_file_name)

    log("Proceeding with: length={}, amount={}, rounds={}, n={}".format(key_length, tuple_amount, rounds, n))

    # Generate random key
    main_key = bytearray(os.urandom(key_length))
    log("Using main key: {}".format(main_key), level=0)

    iv_stream_set = []
    for i in range(tuple_amount):
        # Generate random iv
        iv = bytearray(os.urandom(iv_length))
        stream_cipher = fixed_rc4(iv, main_key, cipher_length=rounds * n, n=n)
        iv_stream_set.append((iv, stream_cipher))

    if cache:
        export_cache(iv_stream_set, main_key, key_file_name, data_file_name)
    return iv_stream_set, main_key


def export_cache(iv_stream_set, main_key, key_file_name, data_file_name):
    with open(key_file_name, 'wb') as output:
        output.write(main_key)
    with open(data_file_name, 'w') as output:
        output.write(str(iv_stream_set))


def load_cache(key_file_name, data_file_name):
    with open(key_file_name, 'rb') as file:
        main_key = file.read()
    with open(data_file_name, 'r') as file:
        iv_and_stream_set = eval(file.read())
    return iv_and_stream_set, main_key