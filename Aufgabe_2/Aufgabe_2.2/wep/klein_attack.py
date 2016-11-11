from collections import Counter

from utils import log
from wep.iv_and_cipher_generator import iv_and_stream_key_generator


def get_most_common_byte(data, n=256):
    t_set = []
    for pair in data:
        x_i = pair.get('stream_key')[0]
        # TODO: Zahlenraum anpassen
        t_i = (1 - x_i) % n
        t_set.append(t_i)
    return Counter(t_set).most_common(1)[0]


def calculate_key_byte(t, n):
    # Average case t = K[0] + K[1] + 1
    for i in range(n):
        k_0 = i
        k_1 = t - k_0 - 1
        yield k_1


if __name__ == '__main__':
    n = 256
    tuple_amount = 500
    # Retrieve sample set of bytearray tuples
    stream_key, main_key = iv_and_stream_key_generator(tuple_amount=tuple_amount)
    # Logging
    #log("First bytes of main key: {}".format((main_key[0], main_key[1], main_key[2])), level=0)
    #log("Estimated value: {} = K[0] + K[1] + 1".format((main_key[0] + main_key[1] + 1) % n), level=0)
    # Observation of first bytes
    #t = get_most_common_byte(stream_key)
    #log("Most common byte: {}, P({})={}".format(t[0], t[0], t[1] / tuple_amount), level=0)
    # Calculate
    #k_generator = calculate_key_byte(t[0], n)
    #for k in k_generator:
    #    for pair in stream_key:
    #        stream_key = pair.get('stream_key')
    #        if k == stream_key[0]:
    #            print(k)

    j = stream_key[0].get('iv')[-1]
    i_1 = stream_key[0].get('iv')[-2]


    # Initialization
    s = []
    for i in range(n):
        s.append(i)
    s = bytearray(s)

    k = bytearray(stream_key[0].get('iv'))

    for i in range(len(k)):  # TODO: check if modulo works as expected
        j = (j + s[i] + k[i % len(k)]) % n
        s[i], s[j] = s[j], s[i]

    output = ""
    for i in range(len(s)):
        output += str(s[i])+", "
    print(output)
    print("K[b-2]="+hex(j))
    print("K[b-1]="+hex(i))
    print("S[b]="+hex(s[len(stream_key[0].get('iv'))]))
    fick = ((j + i_1 - s[len(stream_key[0].get('iv'))])%256)
    print("K[b]= K[b-2] + K[b-1] - S[b] ")
    print("K[b] tatsächlich :="+str(main_key[0]))
    print("K[b] berechnet:="+str(fick))

