# Set log_level to zero to disable logging
import datetime

log_level = 2


def log(text, level=1):
    if log_level >= level:
        print(text)

