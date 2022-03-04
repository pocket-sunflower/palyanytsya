import os
import sys

from humanfriendly.terminal import ansi_wrap
from requests import get

from MHDDoS.start import ToolsConsole


def supports_color():
    platform = sys.platform
    supported_platform = platform != 'Pocket PC' and (platform != 'win32' or 'ANSICON' in os.environ)

    # isatty is not always implemented, #6223.
    is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
    return supported_platform and is_a_tty


def print_vpn_warning():
    WARNING_YELLOW = (236, 232, 26)

    local_ip = get('http://ip.42.pl/raw').text
    ip_data = ToolsConsole.info(local_ip)

    print(ansi_wrap("!!! WARNING:\n"
                    f"   Please, MAKE SURE that you are using VPN.\n"
                    f"   Your current data is:\n"
                    f"      IP: {ip_data['ip']}\n"
                    f"      Country: {str.upper(ip_data['country'])}\n"
                    f"   If the data above doesn't match your physical location, you can ignore this warning.\n"
                    f"   Stay safe! ♥\n", color=(WARNING_YELLOW if supports_color() else None)))
