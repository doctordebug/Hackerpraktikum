from Aufgabe_2.Aufgabe_2_2.rc4.key_scheduling import key_scheduling
from Aufgabe_2.Aufgabe_2_2.rc4.pseudo_random_generator import pseudo_random_generator


def fixed_rc4(iv, main_key, cipher_length=4096, n=256):
    """
    Method for returning a fixed length of a stream cipher
    :param iv: The initialization vector for rc4
    :param main_key: Main or root key for rc4
    :param cipher_length: length of the stream cipher in bytes
    :param n: Base of the integer group
    :return: Returns the stream cipher of length cipher_length
    """
    # Session key
    session_key = iv + main_key
    # Initial permutation
    s_box = key_scheduling(session_key, n=n)
    stream_cipher = bytearray()
    # Extract cipher_length stream key bytes
    for k in pseudo_random_generator(s_box):
        stream_cipher += k
        if len(stream_cipher) >= cipher_length:
            break
    return stream_cipher
