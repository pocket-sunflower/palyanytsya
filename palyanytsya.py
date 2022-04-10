import time
from multiprocessing import Queue

import colorama
from humanfriendly.terminal import *

from utils.gui import GUI
from utils.input_args import parse_command_line_args
from utils.logs import logger
from utils.misc import print_vpn_warning, supports_complex_colors
from utils.supervisor import AttackSupervisor


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

    args = parse_command_line_args()

    attacks_state_queue = Queue()
    supervisor_state_queue = Queue()

    AttackSupervisor(args, attacks_state_queue, supervisor_state_queue).start()
    # GUI(args, attacks_state_queue, supervisor_state_queue).start()

    while True:
        time.sleep(1)


if __name__ == '__main__':
    colorama.init()

    try:
        velyka_kara()
    except KeyboardInterrupt:
        print("\nExecution aborted (Ctrl+C).\n")
    except SystemExit:
        pass

    colorama.deinit()

    input("\nExecution finished.\nPress ENTER to exit... ")
