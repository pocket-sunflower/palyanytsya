import logging
import multiprocessing
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


class SafeQueueListener(QueueListener):
    def _monitor(self):
        """
        Monitor the queue for records, and ask the handler
        to deal with them.

        This method runs on a separate, internal thread.
        The thread will terminate if it sees a sentinel object in the queue.
        """
        try:
            q = self.queue
            has_task_done = hasattr(q, 'task_done')
            while True:
                try:
                    record = self.dequeue(True)
                    if record is self._sentinel:
                        if has_task_done:
                            q.task_done()
                        break
                    self.handle(record)
                    if has_task_done:
                        q.task_done()
                except Empty:
                    break
        except Exception as e:
            pass


def initialize_logging(no_gui: bool = True) -> Queue:
    logging_queue = Queue()

    # this writes to file
    file_handler = TimedRotatingFileHandler(
            filename="logs/log.txt",
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

    # this collect logs from all process loggers created by get_logger_for_current_process()
    queue_listener = SafeQueueListener(
        logging_queue,
        *handlers,
        respect_handler_level=False
    )
    queue_listener.start()

    return logging_queue


def get_logger_for_current_process(logging_queue: Queue, name: str = None) -> logging.Logger:
    if logging_queue is None:
        raise RuntimeError(f"A logging queue is required to initialize a process logger "
                           f"(process {multiprocessing.current_process().pid} '{multiprocessing.current_process().name}', "
                           f"thread '{threading.current_thread().name}').")

    logger = logging.getLogger(name)
    logger.handlers = [
        QueueHandler(logging_queue)
    ]
    logger.setLevel("INFO")

    # from blessed import Terminal
    # t = Terminal()
    # print(t.pink(f"Initialized logger: {name} {multiprocessing.Process.pid} {logging_queue.__hash__()}"))

    return logger
