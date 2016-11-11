from wep.iv_and_cipher_generator import iv_and_stream_key_generator
from collections import Counter


def observe_first_bytes(data, n=256):
    t_set = []
    for pair in data[:len(data)-1]:
        x_i = pair.get('stream_key')[0]
        #TODO: Zahlenraum anpassen
        t_i = (1 - x_i) % n
        t_set.append(t_i)
    print(Counter(t_set).most_common(3))
    print(t_set)

if __name__ == '__main__':

    # Retrieve sample set of bytearray tuples
    data = iv_and_stream_key_generator(tuple_amount=45000)
    observe_first_bytes(data)