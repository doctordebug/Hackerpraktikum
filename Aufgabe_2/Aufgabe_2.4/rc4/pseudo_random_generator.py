from utils import log


def pseudo_random_generator(s, n=256):
    """
    Pseudo random generator method as described in "Attacks on the RC4 stream cipher"
    :param s: Permuted s-box
    :param n: Base of the integer group
    :return: (rounds * n) pseudo random bytes
    """
    if len(s) != n:
        print("Length of S-Box and n doesn't match")
        exit()

    #log("Proceeding with: s={}, n={}".format(s, n))

    # Initialization
    i, j = 0, 0

    # Generate pseudo random sequence
    while True:  # TODO: check if modulo works as expected
        i = (i + 1) % n
        j = (j + s[i]) % n
        s[i], s[j] = s[j], s[i]
        k = (s[i] + s[j]) % n
        yield bytes([s[k]])
