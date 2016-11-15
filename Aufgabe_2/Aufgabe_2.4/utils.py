# Set log_level to zero to disable logging
log_level = 0
def log(text, level=1):
    if log_level >= level:
        print(text)
