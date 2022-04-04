"""
Miscellaneous utilities used by MHDDoS.
"""

import ctypes
from multiprocessing import RawValue, Lock


class Counter(object):

    def __init__(self, value=0):
        self._value = RawValue(ctypes.c_longlong, value)
        self._lock = Lock()

    def __iadd__(self, value):
        with self._lock:
            self._value.value += value
        return self

    def __int__(self):
        return self._value.value

    def set(self, value):
        with self._lock:
            self._value.value = value
        return self
