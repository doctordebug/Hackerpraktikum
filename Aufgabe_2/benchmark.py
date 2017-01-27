import os
import sys

sys.path.insert(0, os.path.join(os.getcwd(), '..'))

file = os.path.join(os.getcwd(), "Aufgabe_2_4/fast_attack.py")
with open(file) as f:
    code = compile(f.read(), file, 'exec')
    exec(code, None, None)
