import time
from multiprocessing import Queue

import colorama
from humanfriendly.terminal import *

from utils.gui import GUI, get_flair_string
from utils.input_args import parse_command_line_args
from utils.misc import print_vpn_warning
from utils.supervisor import AttackSupervisor


def print_flair():
    print(get_flair_string())
    print(ansi_wrap("Initializing...\n", color="green"))


def velyka_kara():
    print_flair()
    # print_vpn_warning()

    args = parse_command_line_args()
    # time.sleep(1)

    attacks_state_queue = Queue()
    supervisor_state_queue = Queue()

    AttackSupervisor(args, attacks_state_queue, supervisor_state_queue).start()
    GUI(args, attacks_state_queue, supervisor_state_queue).start()

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

    # input("\nExecution finished.\nPress ENTER to exit... ")
