import multiprocessing

from utils.input_args import parse_command_line_args
from utils.tui.tui import run_tui


def krasyva_kara():
    run_tui()


if __name__ == '__main__':
    multiprocessing.set_start_method("spawn", force=True)  # required for Windows support

    # args = parse_command_line_args()
    # logging_queue = initialize_logging(args.no_gui)

    krasyva_kara()

    # input("Execution finished.\nPress ENTER to exit... ")
