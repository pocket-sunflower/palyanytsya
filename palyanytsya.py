import multiprocessing
import time
from multiprocessing import Queue

import colorama
from blessed import Terminal
from humanfriendly.terminal import *

from utils.blessed_utils import KeyboardListener
from utils.gui import GUI, get_flair_string
from utils.input_args import parse_command_line_args
from utils.logs import get_logger_for_current_process, initialize_logging
from utils.supervisor import AttackSupervisor


def print_flair():
    print(get_flair_string())
    print(ansi_wrap("Initializing...\n", color="green"))


def velyka_kara():
    print_flair()
    # print_vpn_warning()

    args = parse_command_line_args()
    # time.sleep(1)

    logging_queue = initialize_logging(args.no_gui)
    logger = get_logger_for_current_process(logging_queue, "PALYANYTSYA")

    attacks_state_queue = Queue()
    supervisor_state_queue = Queue()
    AttackSupervisor(args, attacks_state_queue, supervisor_state_queue, logging_queue).start()
    if not args.no_gui:
        GUI(args, attacks_state_queue, supervisor_state_queue, logging_queue).start()

    try:
        while True:
            time.sleep(1)
    except Exception:
        logging_queue.put(None)


if __name__ == '__main__':
    multiprocessing.set_start_method("spawn", force=True)  # required for Windows support
    colorama.init()

    try:
        velyka_kara()
    except Exception as e:
        print(f"Exception: {e}")
    except KeyboardInterrupt:
        print("\nExecution aborted (Ctrl+C).\n")
    except SystemExit:
        pass

    colorama.deinit()

    # input("\nExecution finished.\nPress ENTER to exit... ")
