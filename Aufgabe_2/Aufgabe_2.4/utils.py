from rc4 import rc4

# Set log_level to zero to disable logging
log_level = 2


def log(text, level=1):
    if log_level >= level:
        print(text)

