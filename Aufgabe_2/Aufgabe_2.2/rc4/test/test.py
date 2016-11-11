import unittest

from rc4.key_scheduling import key_scheduling
from rc4.pseudo_random_generator import pseudo_random_generator


def rc4(key, cipher_length=4096):
    s_box = key_scheduling(key)
    cipher = bytearray()
    for k in pseudo_random_generator(s_box):
        cipher += k
        if len(cipher) > cipher_length:
            break
    return cipher


class TestRC4(unittest.TestCase):
    def test(self):
        # Key length: 40 bits
        key = bytearray(b'\x01\x02\x03\x04\05')
        test_string_offset_0 = bytearray(b'\xb2\x39\x63\x05\xf0\x3d\xc0\x27\xcc\xc3\x52\x4a\x0a\x11\x18\xa8')
        with open("vectors.txt", 'r') as data:
            txt_vectors = data.read()
        print(txt_vectors.find("Key length"))


if __name__ == '__main__':
    unittest.main()
