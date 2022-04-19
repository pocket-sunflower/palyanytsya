import math
import os
import socket
import sys
import time

from humanfriendly.terminal import ansi_wrap
from requests import get

from MHDDoS.methods.tools import Tools


class TimeInterval:
    interval: float
    _last_interval_timestamp: float

    def __init__(self, interval: float):
        self.interval = interval
        self.reset()

    def check_if_has_passed(self) -> bool:
        time_since_last = time.perf_counter() - self._last_interval_timestamp
        if time_since_last >= self.interval:
            self._last_interval_timestamp = time.perf_counter()
            return True
        else:
            return False

    def reset(self) -> None:
        self._last_interval_timestamp = float("-inf")

    @property
    def time_left(self) -> float:
        time_since_last = time.perf_counter() - self._last_interval_timestamp
        return max(0., self.interval - time_since_last)


def supports_complex_colors():
    platform = sys.platform
    supported_platform = platform != 'Pocket PC' and (platform != 'win32' or 'ANSICON' in os.environ)

    # isatty is not always implemented, #6223.
    is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
    return supported_platform and is_a_tty


def print_vpn_warning():
    WARNING_YELLOW = (236, 232, 26) if supports_complex_colors() else "yellow"

    local_ip = get('http://ip.42.pl/raw').text
    ip_data = Tools.info(local_ip)

    print(ansi_wrap("!!! WARNING:\n"
                    f"   Please, MAKE SURE that you are using VPN.\n"
                    f"   Your current data is:\n"
                    f"      IP: {ip_data['ip']}\n"
                    f"      Country: {str.upper(ip_data['country'])}\n"
                    f"   If the data above doesn't match your physical location, you can ignore this warning.\n"
                    f"   Stay safe! ♥\n", color=WARNING_YELLOW))


def is_valid_ipv4(address: str):
    try:
        socket.inet_aton(address)
        return True
    except socket.error:
        return False
