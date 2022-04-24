import logging
import multiprocessing
import os
import sys
import threading
from io import StringIO
from logging.handlers import TimedRotatingFileHandler, QueueHandler, QueueListener
from multiprocessing import Queue
from queue import Empty

import coloredlogs

logging.basicConfig(format='%(asctime)s %(name)s %(process)s [%(levelname)s] %(message)s',
                    datefmt="%H:%M:%S",
                    handlers=[])

# class BufferedStringHandler(logging.StreamHandler):
#     stream: StringIO
#     _size: int
#
#     def __init__(self, size: int = 1024):
#         self.stream = StringIO()
#         self._size = size
#         logging.StreamHandler.__init__(self, stream=self.stream)
#
#     def emit(self, record: logging.LogRecord) -> None:
#         logging.StreamHandler.emit(self, record)
#         self.stream.truncate(self._size)
#
#
# stream_handler = BufferedStringHandler()
# stream_handler.formatter = coloredlogs.ColoredFormatter(
#     fmt="{asctime} {name} {process} [{levelname}] {message}",
#     style="{",
#     datefmt="%H:%M:%S"
# )


def initialize_logging(no_gui: bool = True) -> (Queue, QueueListener):
    logging_queue = Queue()

    # this writes to file
    if not os.path.exists("logs"):
        os.mkdir("logs")
    file_handler = TimedRotatingFileHandler(
            filename="logs/palyanytsya.log",
            when='h',
            interval=1,
            backupCount=0,
            encoding='utf-8',
        )
    file_handler.formatter = logging.Formatter(
        fmt="{asctime} {name} {process} [{levelname}] {message}",
        style="{",
        datefmt="%H:%M:%S"
    )

    # this writes to stderr if GUI mode is disabled
    if no_gui:
        stream_handler = logging.StreamHandler(stream=sys.stderr)
        stream_handler.formatter = coloredlogs.ColoredFormatter(
            fmt="{asctime} {name} {process} [{levelname}] {message}",
            style="{",
            datefmt="%H:%M:%S"
        )
    else:
        stream_handler = logging.NullHandler()

    # TODO: attack processes handler (for GUI mode)

    handlers = [
        file_handler,
        stream_handler,
    ]

    # this collects logs from all process loggers created by get_logger_for_current_process()
    queue_listener = QueueListener(
        logging_queue,
        *handlers,
        respect_handler_level=False
    )
    queue_listener.start()

    return logging_queue, queue_listener


def get_logger_for_current_process(logging_queue: Queue, name: str = None, level: str = "INFO") -> logging.Logger:
    if logging_queue is None:
        raise RuntimeError(f"A logging queue is required to initialize a process logger "
                           f"(process {multiprocessing.current_process().pid} '{multiprocessing.current_process().name}', "
                           f"thread '{threading.current_thread().name}').")

    if name is None:
        name = multiprocessing.current_process().name

    logger = logging.getLogger(name)
    logger.handlers = [
        QueueHandler(logging_queue)
    ]
    logger.setLevel(level)

    return logger
