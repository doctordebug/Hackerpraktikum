from utils import log
from wep.iv_and_cipher_generator import iv_and_stream_key_generator
from collections import Counter


def observe_first_bytes(data, n=256):
    t_set = []
    for pair in data[:len(data)-1]:
        x_i = pair.get('stream_key')[0]
        #TODO: Zahlenraum anpassen
        t_i = (1 - x_i) % n
        t_set.append(t_i)
    return Counter(t_set).most_common(1)


if __name__ == '__main__':

    n=256
    # Retrieve sample set of bytearray tuples
    data, main_key = iv_and_stream_key_generator(tuple_amount=50000)
    # Logging
    log("First bytes of main key: {}".format((main_key[0],main_key[1],main_key[2])), level=0)
    log("Estimated value: {}".format((main_key[0] + main_key[1] + 1) % n), level=0)
    # Observation of first bytes
    t = observe_first_bytes(data)
    # Calculate
    print(t)