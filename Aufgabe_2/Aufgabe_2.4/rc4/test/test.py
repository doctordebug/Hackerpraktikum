import unittest

from rc4.rc4 import fixed_rc4
from utils import log


def get_test_vector_set():
    # Parse values
    key_length = "Key length:"
    key = "key:"
    dec = "DEC"
    test_set = []
    counter = -1
    with open("vectors.txt", 'r') as data:
        for line in data:
            key_length_pos = line.find(key_length)
            key_pos = line.find(key)
            dec_pos = line.find(dec)
            if key_length_pos != -1:
                counter += 1
                raw = line[key_length_pos + len(key_length):]
                test_set.append(dict(id=counter, key_length=[int(s) for s in raw.split() if s.isdigit()][0]))
                test_set[counter].update(dict(vectors=[]))
            elif key_pos != -1:
                test_set[counter].update(dict(key=line[key_pos + len(key):].strip()))
            elif dec_pos != -1:
                split = line[dec_pos + len(dec):].split()
                test_set[counter].get('vectors').append(dict(offset=split[0], value=''.join(split[3:])))
    return test_set


class TestRC4(unittest.TestCase):
    def test_vectors(self):
        test_set = get_test_vector_set()

        for entry in test_set:
            id = entry.get('id')
            key = bytearray.fromhex(entry.get('key')[2:])
            vector_set = entry.get('vectors')
            log("Testing set {}, using key {} ".format(id + 1, key), level=0)
            for vector in vector_set:
                offset = int(vector.get('offset'))
                expected_output = bytearray.fromhex(vector.get('value'))
                output_to_test = fixed_rc4(key, cipher_length=offset + len(expected_output), n=256)
                # Test
                assert output_to_test[-len(expected_output):] == expected_output, \
                    print("Mismatch in cipher stream! Test set: {}, expected: {},"
                          " got: {}".format(id, expected_output, output_to_test[-len(expected_output):]))


if __name__ == '__main__':
    unittest.main()
