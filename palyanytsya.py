import multiprocessing
import sys
import threading
import time
from multiprocessing import Queue

import colorama
from humanfriendly.terminal import *

from utils.gui import GUI, get_flair_string
from utils.input_args import parse_command_line_args
from utils.logs import get_logger_for_current_process, initialize_logging
from utils.supervisor import AttackSupervisor

logger = None


def print_flair():
    print(get_flair_string())
    print(ansi_wrap("Initializing...\n", color="green"))


def velyka_kara():
    print_flair()
    # print_vpn_warning()

    # time.sleep(1)
    global logger
    logger = get_logger_for_current_process(logging_queue, "PALYANYTSYA")

    attacks_state_queue = Queue()
    supervisor_state_queue = Queue()
    supervisor_thread = AttackSupervisor(args, attacks_state_queue, supervisor_state_queue, logging_queue)
    supervisor_thread.start()

    if not args.no_gui:
        gui_thread = GUI(args, attacks_state_queue, supervisor_state_queue, logging_queue)
        gui_thread.start()

    while True:
        time.sleep(1)

        if not supervisor_thread.is_alive():
            logger.error("Supervisor thread is dead. Exiting application.")
            sys.exit()
        if (not args.no_gui) and (not supervisor_thread.is_alive()):
            logger.error("GUI thread is dead. Exiting application.")
            sys.exit()


if __name__ == '__main__':
    multiprocessing.set_start_method("spawn", force=True)  # required for Windows support
    colorama.init()
    args = parse_command_line_args()
    logging_queue = initialize_logging(args.no_gui)

    try:
        velyka_kara()
    except Exception as e:
        print(f"Exception: {e}")
    except KeyboardInterrupt:
        time.sleep(1)
        while True:
            print(f"Running threads: {threading.active_count()}")
            time.sleep(1)
        print("\nExecution aborted (Ctrl+C).\n")
    except SystemExit:
        pass

    colorama.deinit()

    # input("\nExecution finished.\nPress ENTER to exit... ")
