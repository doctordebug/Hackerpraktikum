# Set log_level to zero to disable logging
log_level = 2


def log(text, level=1):
    if log_level >= level:
        print(text)

def bytes_to_str(byte_arr):
    return "".join(map(chr, byte_arr))