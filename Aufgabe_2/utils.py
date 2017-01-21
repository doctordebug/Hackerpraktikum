# Set log_level to zero to disable logging
import datetime

log_level = 0


def log(text, level=1):
    if log_level >= level:
        print(text)


def log_timing():
    '''Decorator generator that logs the time it takes a function to execute'''

    # Decorator generator
    def decorator(func_to_decorate):
        def wrapper(*args, **kwargs):
            start = datetime.datetime.now()
            result = func_to_decorate(*args, **kwargs)
            elapsed = (datetime.datetime.now() - start)

            log("[TIMING]:%s - %s" % (func_to_decorate.__name__, elapsed), level=0)
            return result

        wrapper.__doc__ = func_to_decorate.__doc__
        wrapper.__name__ = func_to_decorate.__name__
        return wrapper

    return decorator
