from sys import argv

import colorama
from humanfriendly.terminal import *

from MHDDoS.start import start
from utils import print_vpn_warning, supports_complex_colors


def get_flair_string():
    BLUE = (0, 91, 187) if supports_complex_colors() else "blue"
    YELLOW = (255, 213, 0) if supports_complex_colors() else "yellow"
    GREEN = (8, 255, 8) if supports_complex_colors() else "green"
    RED = (255, 0, 0) if supports_complex_colors() else "red"

    heart = ansi_wrap("♥", color=RED)

    flair_string = "\n" + \
                   "A heavy-duty freedom-infused MHDDoS wrapper...\n" + \
                   "\n" + \
                   ansi_wrap("██████╗░░█████╗░██╗░░░░░██╗░░░██╗░█████╗░███╗░░██╗██╗░░░██╗████████╗░██████╗██╗░░░██╗░█████╗░\n", color=BLUE) + \
                   ansi_wrap("██╔══██╗██╔══██╗██║░░░░░╚██╗░██╔╝██╔══██╗████╗░██║╚██╗░██╔╝╚══██╔══╝██╔════╝╚██╗░██╔╝██╔══██╗\n", color=BLUE) + \
                   ansi_wrap("██████╔╝███████║██║░░░░░░╚████╔╝░███████║██╔██╗██║░╚████╔╝░░░░██║░░░╚█████╗░░╚████╔╝░███████║\n", color=BLUE) + \
                   ansi_wrap("██╔═══╝░██╔══██║██║░░░░░░░╚██╔╝░░██╔══██║██║╚████║░░╚██╔╝░░░░░██║░░░░╚═══██╗░░╚██╔╝░░██╔══██║\n", color=YELLOW) + \
                   ansi_wrap("██║░░░░░██║░░██║███████╗░░░██║░░░██║░░██║██║░╚███║░░░██║░░░░░░██║░░░██████╔╝░░░██║░░░██║░░██║\n", color=YELLOW) + \
                   ansi_wrap("╚═╝░░░░░╚═╝░░╚═╝╚══════╝░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚══╝░░░╚═╝░░░░░░╚═╝░░░╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝\n", color=YELLOW) + \
                   "\n" + \
                   f"                                                                  ...from Ukraine with love {heart}\n"
    return flair_string


def print_flair():
    print(get_flair_string())
    print(ansi_wrap("Initializing...\n", color="green"))


def velyka_kara():
    print_flair()
    print_vpn_warning()

    # override script name
    argv[0] = "palyanytsya.py"

    if len(argv) < 5:
        print("Not enough arguments supplied. Please check the reference below:\n")
        argv.insert(1, "HELP")

    # enable debug to see attack progress
    argv.append("true")

    start()


if __name__ == '__main__':
    colorama.init()

    try:
        velyka_kara()
    except KeyboardInterrupt:
        print("\nExecution aborted.\n")
    except SystemExit:
        pass

    colorama.deinit()

    input("\nExecution finished.\nPress ENTER to exit... ")
