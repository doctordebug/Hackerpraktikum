from Aufgabe_2.Aufgabe_2_2.wep.klein_attack import crack_wep
from Aufgabe_2.Aufgabe_2_4.fast_attack import read_cap_file, test_keys

if __name__ == '__main__':
    key_length_bytes = 13
    tuple_amount = 300000

    # Info
    print("Using key length of {} bytes".format(key_length_bytes))
    print("Using {} tuples".format(tuple_amount))

    # Retrieve sample set of bytearray tuples
    iv_stream_pair = read_cap_file("wep-128_1min.cap", tuple_amount=tuple_amount)
    iv_stream_pair.extend(read_cap_file("wep-128_2min.cap", tuple_amount=tuple_amount))

    print("Start Hacking")
    possible_key = crack_wep(iv_stream_pair, key_length_bytes, 256, tuple_amount)
    test_keys(iter([possible_key]), (iv_stream_pair[0][0], iv_stream_pair[0][1]))
