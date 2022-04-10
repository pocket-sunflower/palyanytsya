import logging
from io import StringIO
from logging.handlers import TimedRotatingFileHandler

import coloredlogs

logger = logging.getLogger("PALYANYTSYA")

file_handler = TimedRotatingFileHandler(
        filename="log.txt",
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


class BufferedStringHandler(logging.StreamHandler):
    stream: StringIO
    _size: int

    def __init__(self, size: int = 1024):
        self.stream = StringIO()
        self._size = size
        logging.StreamHandler.__init__(self, stream=self.stream)

    def emit(self, record: logging.LogRecord) -> None:
        logging.StreamHandler.emit(self, record)
        self.stream.truncate(self._size)


stream_handler = BufferedStringHandler()
stream_handler.formatter = coloredlogs.ColoredFormatter(
    fmt="{asctime} {name} {process} [{levelname}] {message}",
    style="{",
    datefmt="%H:%M:%S"
)

logger.handlers = [
    file_handler,
    stream_handler
]

logger.setLevel("INFO")
