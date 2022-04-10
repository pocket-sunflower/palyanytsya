import time
from multiprocessing import Queue
from threading import Thread

from utils.input_args import Arguments


class GUI(Thread):
    """GUI thread of Palyanytsya."""
    _update_interval: float

    def __init__(self,
                 args: Arguments,
                 attacks_state_queue: Queue,
                 supervisor_state_queue: Queue,
                 update_interval: float = 1):
        Thread.__init__(self, daemon=True)
        self._args = args
        self._attacks_state_queue = attacks_state_queue
        self._supervisor_state_queue = supervisor_state_queue
        self._update_interval = update_interval

    def run(self):
        while True:
            time.sleep(self._update_interval)
