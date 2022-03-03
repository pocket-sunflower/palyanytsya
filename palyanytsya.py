import sys
from sys import argv

from humanfriendly.terminal import *
from requests import get

from MHDDoS.start import start, ToolsConsole


def print_flair():

    BLUE = (0, 91, 187)
    YELLOW = (255, 213, 0)
    GREEN = (8, 255, 8)
    RED = (255, 0, 0)

    heart = ansi_wrap("♥", color=(RED if sys.platform != "win32" else None))

    flair_string = "\n" + \
                   "A heavy-duty freedom-infused MHDDoS wrapper...\n" + \
                   "\n" + \
                   ansi_wrap("██████╗░░█████╗░██╗░░░░░██╗░░░██╗░█████╗░███╗░░██╗██╗░░░██╗████████╗░██████╗██╗░░░██╗░█████╗░\n", color=(BLUE if sys.platform != "win32" else None)) + \
                   ansi_wrap("██╔══██╗██╔══██╗██║░░░░░╚██╗░██╔╝██╔══██╗████╗░██║╚██╗░██╔╝╚══██╔══╝██╔════╝╚██╗░██╔╝██╔══██╗\n", color=(BLUE if sys.platform != "win32" else None)) + \
                   ansi_wrap("██████╔╝███████║██║░░░░░░╚████╔╝░███████║██╔██╗██║░╚████╔╝░░░░██║░░░╚█████╗░░╚████╔╝░███████║\n", color=(BLUE if sys.platform != "win32" else None)) + \
                   ansi_wrap("██╔═══╝░██╔══██║██║░░░░░░░╚██╔╝░░██╔══██║██║╚████║░░╚██╔╝░░░░░██║░░░░╚═══██╗░░╚██╔╝░░██╔══██║\n", color=(YELLOW if sys.platform != "win32" else None)) + \
                   ansi_wrap("██║░░░░░██║░░██║███████╗░░░██║░░░██║░░██║██║░╚███║░░░██║░░░░░░██║░░░██████╔╝░░░██║░░░██║░░██║\n", color=(YELLOW if sys.platform != "win32" else None)) + \
                   ansi_wrap("╚═╝░░░░░╚═╝░░╚═╝╚══════╝░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚══╝░░░╚═╝░░░░░░╚═╝░░░╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝\n", color=(YELLOW if sys.platform != "win32" else None)) + \
                   "\n" + \
                   f"                                                                  ...from Ukraine with love {heart}\n"
    print(flair_string)
    print(ansi_wrap("Initializing...\n", color=(GREEN if sys.platform != "win32" else None)))


def print_vpn_warning():
    WARNING_YELLOW = (236, 232, 26)

    local_ip = get('http://ip.42.pl/raw').text
    ip_data = ToolsConsole.info(local_ip)

    print(ansi_wrap("!!! WARNING:\n"
                    f"   Please, MAKE SURE that you are using VPN.\n"
                    f"   Your current data is:\n"
                    f"      IP: {ip_data['ip']}\n"
                    f"      Country: {str.upper(ip_data['country'])}", color=(WARNING_YELLOW if sys.platform != "win32" else None)))
    print(f"   If the data above doesn't match your physical location, you can ignore this warning.\n"
          f"   Stay safe! ♥\n")


def velyka_kara():
    print_flair()
    print_vpn_warning()

    if len(argv) < 5:
        print("Not enough arguments supplied. Please check the reference below:\n")
        argv.insert(1, "HELP")

    start()


if __name__ == '__main__':
    try:
        velyka_kara()
    except KeyboardInterrupt:
        print("\nExecution aborted.\n")
    except SystemExit:
        pass

    input("\nExecution finished.\nPress ENTER to exit... ")
