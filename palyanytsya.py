from sys import argv

from humanfriendly.terminal import *

from MHDDoS.start import start
from utils import print_vpn_warning, supports_color


def print_flair():
    BLUE = (0, 91, 187)
    YELLOW = (255, 213, 0)
    GREEN = (8, 255, 8)
    RED = (255, 0, 0)

    heart = ansi_wrap("♥", color=(RED if supports_color() else None))

    flair_string = "\n" + \
                   "A heavy-duty freedom-infused MHDDoS wrapper...\n" + \
                   "\n" + \
                   ansi_wrap("██████╗░░█████╗░██╗░░░░░██╗░░░██╗░█████╗░███╗░░██╗██╗░░░██╗████████╗░██████╗██╗░░░██╗░█████╗░\n", color=(BLUE if supports_color() else None)) + \
                   ansi_wrap("██╔══██╗██╔══██╗██║░░░░░╚██╗░██╔╝██╔══██╗████╗░██║╚██╗░██╔╝╚══██╔══╝██╔════╝╚██╗░██╔╝██╔══██╗\n", color=(BLUE if supports_color() else None)) + \
                   ansi_wrap("██████╔╝███████║██║░░░░░░╚████╔╝░███████║██╔██╗██║░╚████╔╝░░░░██║░░░╚█████╗░░╚████╔╝░███████║\n", color=(BLUE if supports_color() else None)) + \
                   ansi_wrap("██╔═══╝░██╔══██║██║░░░░░░░╚██╔╝░░██╔══██║██║╚████║░░╚██╔╝░░░░░██║░░░░╚═══██╗░░╚██╔╝░░██╔══██║\n", color=(YELLOW if supports_color() else None)) + \
                   ansi_wrap("██║░░░░░██║░░██║███████╗░░░██║░░░██║░░██║██║░╚███║░░░██║░░░░░░██║░░░██████╔╝░░░██║░░░██║░░██║\n", color=(YELLOW if supports_color() else None)) + \
                   ansi_wrap("╚═╝░░░░░╚═╝░░╚═╝╚══════╝░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚══╝░░░╚═╝░░░░░░╚═╝░░░╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝\n", color=(YELLOW if supports_color() else None)) + \
                   "\n" + \
                   f"                                                                  ...from Ukraine with love {heart}\n"
    print(flair_string)
    print(ansi_wrap("Initializing...\n", color=(GREEN if supports_color() else None)))


def velyka_kara():
    print_flair()
    print_vpn_warning()

    if len(argv) < 5:
        print("Not enough arguments supplied. Please check the reference below:\n")
        argv.insert(1, "HELP")

    # enable debug to see attack progress
    argv.append("true")

    start()


if __name__ == '__main__':
    try:
        velyka_kara()
    except KeyboardInterrupt:
        print("\nExecution aborted.\n")
    except SystemExit:
        pass

    input("\nExecution finished.\nPress ENTER to exit... ")
