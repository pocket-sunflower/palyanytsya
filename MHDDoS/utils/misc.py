"""
Miscellaneous utilities used by MHDDoS.
"""

import ctypes
from multiprocessing import Queue, Lock
from multiprocessing.sharedctypes import RawValue
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


def get_last_from_queue(queue: Queue, default_value: Any = None) -> Any | None:
    """
    Drains the queue and returns the last item put into it.

    Args:
        queue: Queue to get the item from.
        default_value: If this value is provided and the queue is empty, this value will be returned.

    Returns:
        Last item if the queue was not empty, None otherwise.
    """
    result = default_value
    try:
        while True:
            result = queue.get_nowait()
    except Empty:
        return result
