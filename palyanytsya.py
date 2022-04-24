import multiprocessing
import sys
import time
from multiprocessing import Queue

import colorama
from humanfriendly.terminal import *


from utils.gui import GUI, get_flair_string
from utils.input_args import parse_command_line_args
from utils.logs import get_logger_for_current_process, initialize_logging
from utils.supervisor import AttackSupervisor
from utils.tui.tui import run_tui

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

    gui_thread = None
    if not args.no_gui:
        gui_thread = GUI(args, attacks_state_queue, supervisor_state_queue, logging_queue)
        gui_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(flush=True)
        pass
    except SystemExit:
        pass
    finally:
        logger.info("Exiting...")

        if supervisor_thread:
            logger.info("Stopping supervisor...")
            supervisor_thread.stop()
            supervisor_thread.join()
        if gui_thread:
            logger.info("Stopping GUI...")
            gui_thread.stop()
            gui_thread.join()

        logger.info("Exited.")
        logging_queue.put(None)
        time.sleep(0.5)


def krasyva_kara():
    run_tui()


if __name__ == '__main__':
    multiprocessing.set_start_method("spawn", force=True)  # required for Windows support

    args = parse_command_line_args()
    # logging_queue = initialize_logging(args.no_gui)

    krasyva_kara()

    # input("Execution finished.\nPress ENTER to exit... ")
