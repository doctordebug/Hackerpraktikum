from utils import log


def key_scheduling(k=bytearray(), n=256):
    """
    Key scheduling method as described in "Attacks on the RC4 stream cipher"
    :param k: Random key
    :param n: Base of the integer group
    :return: An initial permuted s-box
    """
    if len(k) > n or len(k) == 0:
        print("Invalid parameter for k")
        exit()

    log("Proceeding with: k={}, n={}".format(k, n))

    # Initialization
    s = []
    for i in range(n):
        s.append(i)
    s = bytearray(s)

    j = 0
    # Generate a random permutation
    for i in range(n):  # TODO: check if modulo works as expected
        j = (j + s[i] + k[i % len(k)]) % n
        s[i], s[j] = s[j], s[i]
    return s
