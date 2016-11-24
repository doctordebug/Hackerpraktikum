# Set log_level to zero to disable logging
import datetime

log_level = 2


def log(text, level=1):
    if log_level >= level:
        print(text)


def stop_time(func):
    def func_wrapper(name):
        start = datetime.datetime.now()
        func()  # Prove that function definition has completed
        ms_end = int((datetime.datetime.now() - start).total_seconds() * 1000)
        print(ms_end)

    return func_wrapper
