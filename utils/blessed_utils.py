import time
from threading import Thread
from typing import Callable

from blessed import Terminal


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


def pad_text(text: str, term: Terminal):
    text_h = text_height(text)
    text_w = text_width(text, term)
    return pad_to_box(text, text_w, text_h, term)


def pad_to_box(text: str,
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


def wrap_text_in_border(text: str, term: Terminal):
    text = pad_text(text, term)
    text_w = text_width(text, term)
    lines = text.split("\n")
    border_top = "╭" + "─" * text_w + "╮"
    for i in range(len(lines)):
        lines[i] = "│" + lines[i] + "│"
    border_bottom = "╰" + "─" * text_w + "╯"
    bordered = border_top + "\n" + "\n".join(lines) + border_bottom
    return bordered


def center_text(text: str, term: Terminal) -> str:
    text_h = text_height(text)
    text_w = text_width(text, term)
    text = pad_to_box(text, text_h, text_w, term)
    return "\n".join([term.center(line) for line in text.split("\n")])


def print_and_flush(string: str):
    print(string, end="", flush=True)


def clear_screen(term: Terminal):
    print_and_flush(term.home + term.clear)


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

    _term: Terminal
    _bordered: bool
    _content_buffer: str = ""

    def __init__(self,
                 term: Terminal,
                 bordered: bool = False):
        self._term = term
        self._bordered = bordered

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

    def update_content(self, string: str):
        self._content_buffer = string

    def redraw(self):
        term = self._term

        c_width = self.width
        c_height = self.height
        if self._bordered:
            c_width -= 2
            c_height -= 2

        content = self._content_buffer
        # content = "\n" + term.black_on_white(f" Window size: {self.width}x{self.height} ")
        content = truncate_text_to_box(content, c_width, c_height, self._term)
        content = pad_to_box(content, c_width, c_height, self._term)
        content = term.on_black(content)
        if self._bordered:
            content = wrap_text_in_border(content, term)

        with term.location(self.pos_x, self.pos_y):
            print_and_flush(content)
