"""
Miscellaneous utilities used by MHDDoS.
"""

import ctypes
from dataclasses import dataclass
from multiprocessing import RawValue, Lock
from typing import List

from icmplib import Host
from requests import Response, RequestException


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


@dataclass
class AttackState:
    # identification
    attack_pid: int

    # performance
    active_threads_count: int
    time_since_last_packet_sent: float

    # connectivity
    used_proxies_count: int
    connectivity_l7: List[Response | RequestException]
    connectivity_l4: List[Host]

    # throughput
    total_packets_sent: int
    packets_per_second: int
    total_bytes_sent: int
    bytes_per_second: int


