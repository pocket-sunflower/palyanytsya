import multiprocessing
import queue

from utils.input_args import parse_command_line_args
from utils.logs import initialize_logging, get_logger_for_current_process
from utils.supervisor import AttackSupervisor
from utils.tui.tui import run_tui


def velyka_kara():
    if args.no_gui:
        AttackSupervisor(args, queue.Queue(), logging_queue).run()
    else:
        run_tui(args=args, logging_queue=logging_queue)


if __name__ == '__main__':
    multiprocessing.set_start_method("spawn", force=True)  # required for Windows support

    args = parse_command_line_args()
    logging_queue, log_listener = initialize_logging(args.no_gui)

    logger = get_logger_for_current_process(logging_queue)
    logger.info("PALYANYTSYA is starting.")

    try:
        velyka_kara()
    finally:
        log_listener.stop()

    # input("Execution finished.\nPress ENTER to exit... ")
