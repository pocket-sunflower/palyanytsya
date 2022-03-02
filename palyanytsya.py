from sys import argv

from humanfriendly.terminal import *

from MHDDoS.start import start


def print_flair():

    BLUE = (0, 91, 187)
    YELLOW = (255, 213, 0)
    GREEN = (8, 255, 8)
    RED = (255, 0, 0)

    heart = ansi_wrap("♥", color=RED)
    flair_string = "\n" + \
                   "A freedom-infused MHDDoS wrapper...\n" + \
                   "\n" + \
                   ansi_wrap("██████╗░░█████╗░██╗░░░░░██╗░░░██╗░█████╗░███╗░░██╗██╗░░░██╗████████╗░██████╗██╗░░░██╗░█████╗░\n", color=BLUE) + \
                   ansi_wrap("██╔══██╗██╔══██╗██║░░░░░╚██╗░██╔╝██╔══██╗████╗░██║╚██╗░██╔╝╚══██╔══╝██╔════╝╚██╗░██╔╝██╔══██╗\n", color=BLUE) + \
                   ansi_wrap("██████╔╝███████║██║░░░░░░╚████╔╝░███████║██╔██╗██║░╚████╔╝░░░░██║░░░╚█████╗░░╚████╔╝░███████║\n", color=BLUE) + \
                   ansi_wrap("██╔═══╝░██╔══██║██║░░░░░░░╚██╔╝░░██╔══██║██║╚████║░░╚██╔╝░░░░░██║░░░░╚═══██╗░░╚██╔╝░░██╔══██║\n", color=YELLOW) + \
                   ansi_wrap("██║░░░░░██║░░██║███████╗░░░██║░░░██║░░██║██║░╚███║░░░██║░░░░░░██║░░░██████╔╝░░░██║░░░██║░░██║\n", color=YELLOW) + \
                   ansi_wrap("╚═╝░░░░░╚═╝░░╚═╝╚══════╝░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚══╝░░░╚═╝░░░░░░╚═╝░░░╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝\n", color=YELLOW) + \
                   "\n" + \
                   f"                                                                  ...from Ukraine with love {heart}\n"
    print(flair_string)
    print(ansi_wrap("Initializing...\n", color=GREEN))


def velyka_kara():
    print_flair()

    if len(argv) < 5:
        print("Not enough arguments supplied. Please check the reference below:\n")

    start()


if __name__ == '__main__':
    velyka_kara()
