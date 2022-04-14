import threading
import time
from threading import Thread
from typing import Callable, Dict

from blessed import Terminal
from blessed.keyboard import Keystroke


def text_width(text: str, term: Terminal) -> int:
    width = 0
    for line in text.split("\n"):
        line = term.strip_seqs(line)
        if len(line) > width:
            width = len(line)
    return width


def text_height(text: str) -> int:
    height = 1 + text.count("\n")
    return height


def truncate_text_horizontal(text: str, width: int, term: Terminal) -> str:
    return "\n".join([term.truncate(line, width) for line in text.split("\n")])


def truncate_text_vertical(text: str, height: int, term: Terminal) -> str:
    lines = text.split("\n")
    height = max(0, height)
    lines = lines[:height]
    return "\n".join(lines)


def truncate_text_to_box(text: str, width: int, height: int, term: Terminal) -> str:
    text = truncate_text_vertical(text, height, term)
    text = truncate_text_horizontal(text, width, term)
    return text


def color_text(text: str, color: Callable[[str], str] | None) -> str:
    if color is None:
        return text

    text = "\n".join([color(m) for m in text.split("\n")])
    return text


def pad_text_to_itself(text: str, term: Terminal):
    text_h = text_height(text)
    text_w = text_width(text, term)
    return pad_text_to_box(text, text_w, text_h, term)


def pad_text_to_box(text: str,
                    width: int,
                    height: int,
                    term: Terminal,
                    fillchar: str = " ",
                    top: int = None,
                    left: int = None,
                    right: int = None,
                    bottom: int = None) -> str:
    text_h = text_height(text)
    text = "\n".join([term.ljust(line, width, fillchar) for line in text.split("\n")])
    if height > text_h:
        text.removesuffix("\n")
        remaining_lines_count = height - text_h
        text += ("\n" + width * " ") * remaining_lines_count
    return text


def wrap_text_in_border(text: str,
                        term: Terminal,
                        vertical_char="│",
                        horizontal_char="─",
                        top_left_char="╭",
                        top_right_char="╮",
                        bottom_left_char="╰",
                        bottom_right_char="╯"):
    text = pad_text_to_itself(text, term)
    text_w = text_width(text, term)
    lines = text.split("\n")
    border_top = top_left_char + horizontal_char * text_w + top_right_char
    for i in range(len(lines)):
        lines[i] = vertical_char + lines[i] + vertical_char
    border_bottom = bottom_left_char + horizontal_char * text_w + bottom_right_char
    bordered = border_top + "\n" + "\n".join(lines) + "\n" + border_bottom
    return bordered


def center_text(text: str, term: Terminal, width: int = None) -> str:
    text_h = text_height(text)
    text_w = text_width(text, term)
    text = pad_text_to_box(text, text_h, text_w, term)
    return "\n".join([term.center(line, width) for line in text.split("\n")])


def print_and_flush(string: str):
    print(string, end="", flush=True)


def clear_screen(term: Terminal):
    print_and_flush(term.home + term.clear)


class KeyboardListener:
    """Provides a way to capture key presses in terminal."""
    _term: Terminal
    _on_press_callback: Callable[[Keystroke], None]

    _timeout: float = 0.01
    _last_key_presses: Dict[str, float] = {}
    _same_key_interval: float = 0.1

    def __init__(self, term: Terminal, on_key_callback: Callable[[Keystroke], None]):
        self._term = term
        self._on_press_callback = on_key_callback

        stop_event = threading.Event()
        stop_event.clear()
        self._stop_event = stop_event

        self._reader_thread = Thread(target=self._key_reader, daemon=True)
        self._reader_thread.start()

    def _key_reader(self):
        term = self._term

        with term.cbreak():
            while not self._stop_event.is_set():
                key: Keystroke = term.inkey()

                if key is None:
                    continue

                # respect the interval if the key has been recently pressed
                key_id = key.name if key.is_sequence else key
                time_since_last_callback = time.perf_counter() - self._last_key_presses.get(key_id, 0)
                if time_since_last_callback < self._same_key_interval:
                    continue

                self._last_key_presses[key_id] = time.perf_counter()

                self._on_press_callback(key)

    def stop(self):
        self._stop_event.set()
        self._reader_thread.join()


class ScreenResizeHandler:
    refresh_interval: float
    debug_display: bool
    _term: Terminal
    _callback: Callable

    _last_width: int
    _last_height: int

    def __init__(self, term: Terminal, callback: Callable, refresh_interval: float = 0.001, debug_display: bool = False):
        """
        Executes the given callback every time the terminal screen gets resized.

        Args:
            term: Terminal.
            callback: Callback to execute.
            refresh_interval: Interval between screen size checks (in seconds).
            debug_display: Whether to display current dimensions of the terminal window in its top left corner (for debugging).
        """
        self.refresh_interval = refresh_interval
        self.debug_display = debug_display
        self._term = term
        self._callback = callback

        self._last_width = term.width
        self._last_height = term.height

        Thread(target=self.screen_resize_handler_thread, daemon=True).start()

    def screen_resize_handler_thread(self):
        term = self._term
        while True:
            width = term.width
            height = term.height

            if width != self._last_width or height != self._last_height:
                self._last_width = width
                self._last_height = height

                self._callback()

            if self.debug_display:
                with term.location(0, 0):
                    print_and_flush(term.black_on_pink(f" Terminal size: {term.width}x{term.height} "))

            time.sleep(self.refresh_interval)


class BlessedWindow:
    pos_x: int = 0
    pos_y: int = 0
    max_height: int = None
    max_width: int = None
    has_borders: bool = False
    background_color: Callable[[str], str] = None

    _term: Terminal
    _content_buffer: str = ""

    def __init__(self, term: Terminal):
        self._term = term

    @property
    def height(self):
        max_height = self.max_height
        pos_y = self.pos_y
        term_height = self._term.height
        if (max_height is None) or (max_height <= 0) or (max_height > term_height - pos_y):
            return term_height - pos_y
        else:
            return max_height

    @property
    def width(self):
        max_width = self.max_width
        pos_x = self.pos_x
        term_width = self._term.width
        if (max_width is None) or (max_width <= 0) or (max_width > term_width - pos_x):
            return term_width - pos_x
        else:
            return max_width

    @property
    def width_for_content(self):
        width = self.width
        if self.has_borders:
            width -= 2
        return width

    @property
    def height_for_content(self):
        height = self.height
        if self.has_borders:
            height -= 2
        return height

    def clear_content(self):
        self._content_buffer = ""

    def set_content(self, string: str):
        self._content_buffer = string

    def add_content(self, string: str):
        string = pad_text_to_itself(string, self._term)
        if len(self._content_buffer) > 0:
            self._content_buffer += "\n"
        self._content_buffer += string

    def center_content(self):
        self._content_buffer = center_text(self._content_buffer, self._term, self.width_for_content)

    def redraw(self):
        term = self._term

        # compute content dimensions
        width = self.width_for_content
        height = self.height_for_content

        # crop content to fit in window
        content = self._content_buffer
        content = truncate_text_to_box(content, width, height, self._term)
        content = pad_text_to_box(content, width, height, self._term)
        if self.has_borders:
            content = wrap_text_in_border(content, term)
        if self.background_color is not None:
            content = self.background_color(content)

        with term.location(self.pos_x, self.pos_y):
            print_and_flush(content)
