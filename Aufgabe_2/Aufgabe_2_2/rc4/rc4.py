from Aufgabe_2.Aufgabe_2_2.rc4.key_scheduling import key_scheduling
from Aufgabe_2.Aufgabe_2_2.rc4.pseudo_random_generator import pseudo_random_generator


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
