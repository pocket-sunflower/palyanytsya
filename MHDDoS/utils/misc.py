"""
Miscellaneous utilities used by MHDDoS.
"""

import ctypes
from multiprocessing import RawValue, Lock, Queue
from queue import Empty
from typing import Any


class Counter(object):

    def __init__(self, value=0, value_type=ctypes.c_longlong):
        self._value = RawValue(value_type, value)
        self._lock = Lock()

    def __iadd__(self, value):
        with self._lock:
            self._value.value += value
        return self

    def __int__(self):
        return self._value.value

    def __float__(self):
        return self._value.value

    def set(self, value):
        with self._lock:
            self._value.value = value
        return self


def get_last_from_queue(queue: Queue) -> Any | None:
    """
    Drains the queue and returns the last item put into it.

    Args:
        queue: Queue to get the item from.

    Returns:
        Last item if the queue was not empty, None otherwise.
    """
    result = None
    try:
        while True:
            result = queue.get_nowait()
    except Empty:
        return result
