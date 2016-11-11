from collections import Counter

from utils import log
from wep.iv_and_cipher_generator import iv_and_stream_key_generator


def get_most_common_byte(data, n=256):
    t_set = []
    for pair in data[:len(data) - 1]:
        x_i = pair.get('stream_key')[0]
        # TODO: Zahlenraum anpassen
        t_i = (1 - x_i) % n
        t_set.append(t_i)
    return Counter(t_set).most_common(1)[0][0]


def calculate_key_byte(t):
    print(t)


if __name__ == '__main__':
    n = 256
    # Retrieve sample set of bytearray tuples
    stream_key, main_key = iv_and_stream_key_generator(tuple_amount=50000)
    # Logging
    log("First bytes of main key: {}".format((main_key[0], main_key[1], main_key[2])), level=0)
    log("Estimated value: {}".format((main_key[0] + main_key[1] + 1) % n), level=0)
    # Observation of first bytes
    t = get_most_common_byte(stream_key)
    # Calculate
    k = calculate_key_byte(t)
