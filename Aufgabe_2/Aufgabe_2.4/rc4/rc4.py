from rc4.key_scheduling import key_scheduling
from rc4.pseudo_random_generator import pseudo_random_generator
from utils import log


def fixed_rc4(key, cipher_length=4096, n=256):
    # Initial permutation
    s_box = key_scheduling(key, n=n)
    cipher = bytearray()
    # Extract cipher_length stream key bytes
    for k in pseudo_random_generator(s_box):
        cipher += k
        if len(cipher) >= cipher_length:
            break
    return cipher


def test_keys(key_set, tuple):
    # Implement some feedback function
    log("Got some keys: {}".format(key_set), level=0)
    iv = tuple[0]
    stream = tuple[1]
    for key in key_set:
        calculated_stream = fixed_rc4(iv + key, cipher_length=len(stream))
        if calculated_stream == stream:
            log("Key found: {}".format(key), level=0)
            return key
    return None