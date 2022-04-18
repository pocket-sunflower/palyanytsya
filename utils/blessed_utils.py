from __future__ import annotations

import math
import random
import re
import threading
import time
from enum import IntEnum
from threading import Thread
from typing import Callable, Dict, Any, List

from blessed import Terminal
from blessed.keyboard import Keystroke


def print_no_newline(string: str):
    print(str(string), end="", flush=True)


def clear_screen(term: Terminal):
    print_no_newline(term.home + term.clear)


class TextUtils:
    term = Terminal()

    class Justify(IntEnum):
        LEFT = 0
        RIGHT = 1
        CENTER = 2

    @staticmethod
    def strip_sequences(text: str) -> str:
        """
        Strips non-destructive terminal sequences from the given string, while preserving newlines.
        """
        term = TextUtils.term
        stripped = "\n".join([term.caps_compiled.sub('', line) for line in text.split("\n")])
        return stripped

    @staticmethod
    def width(text: str) -> int:
        term = TextUtils.term

        # older, non-optimized version
        # width = 0
        # for line in text.split("\n"):
        #     line = term.strip_seqs(line)
        #     if len(line) > width:
        #         width = len(line)

        stripped = TextUtils.strip_sequences(text)
        stripped_lines_lengths = [len(line) for line in stripped.split("\n")]
        width = max(stripped_lines_lengths)

        return width

    @staticmethod
    def height(text: str) -> int:
        height = 1 + text.count("\n")
        return height

    @staticmethod
    def _justify_internal(text: str, width: int, fillchar: str, just: Justify) -> str:
        text_lines = text.split("\n")
        lines_range = range(len(text_lines))
        justified_lines = ["" for _ in lines_range]

        for i in lines_range:
            line = text_lines[i]
            stripped_line = TextUtils.strip_sequences(line)
            padding = max(width - len(stripped_line), 0)

            if just == TextUtils.Justify.LEFT:
                justified_lines[i] = line + fillchar * padding
            elif just == TextUtils.Justify.RIGHT:
                justified_lines[i] = fillchar * padding + line
            elif just == TextUtils.Justify.CENTER:
                left_side_padding = math.floor(padding / 2.)
                right_side_padding = math.ceil(padding / 2.)
                justified_lines[i] = fillchar * left_side_padding + line + fillchar * right_side_padding
            else:
                justified_lines[i] = line

        justified = "\n".join(justified_lines)
        return justified

    @staticmethod
    def justify_left(text: str, width: int, fillchar: str = " ") -> str:
        return TextUtils._justify_internal(text, width, fillchar, TextUtils.Justify.LEFT)

    @staticmethod
    def justify_right(text: str, width: int, fillchar: str = " ") -> str:
        return TextUtils._justify_internal(text, width, fillchar, TextUtils.Justify.RIGHT)

    @staticmethod
    def center(text: str, width: int, fillchar: str = " ") -> str:

        # older, non-optimized version
        # term = TextUtils.term
        # text_h = TextUtils.height(text)
        # text_w = TextUtils.width(text)
        # text = TextUtils.pad_to_box(text, text_h, text_w)
        # return "\n".join([term.center(line, width) for line in text.split("\n")])

        text = TextUtils.pad_to_itself(text)
        return TextUtils._justify_internal(text, width, fillchar, TextUtils.Justify.CENTER)

    @staticmethod
    def _truncate_line_internal(line: str, length: int) -> str:
        if len(line) <= length:
            return line

        term = TextUtils.term
        caps_regex: re.Pattern = term.caps_compiled
        last_match_end = 0
        truncate_stop_index = 0
        visual_length = 0

        for match in caps_regex.finditer(line):
            visual_length_increase = match.start() - last_match_end
            next_visual_length = visual_length + visual_length_increase

            if next_visual_length >= length:
                truncate_stop_index = last_match_end + (length - visual_length)
                visual_length = length
                break

            visual_length = next_visual_length
            last_match_end = match.end()
            truncate_stop_index = last_match_end

        if (visual_length < length) and (truncate_stop_index < len(line)):
            for _ in line[truncate_stop_index:]:
                visual_length += 1
                truncate_stop_index += 1
                if visual_length == length:
                    break

        return line[0:truncate_stop_index] + term.normal

    @staticmethod
    def truncate_horizontal(text: str, width: int) -> str:

        # older, non-optimized version
        # term = TextUtils.term
        # truncated = "\n".join([term.truncate(line, width) for line in text.split("\n")])

        truncated = "\n".join([TextUtils._truncate_line_internal(line, width) for line in text.split("\n")])
        return truncated

    @staticmethod
    def truncate_vertical(text: str, height: int) -> str:
        lines = text.split("\n")
        height = max(0, height)
        lines = lines[:height]
        return "\n".join(lines)

    @staticmethod
    def truncate_to_box(text: str, width: int, height: int) -> str:
        text = TextUtils.truncate_vertical(text, height)
        text = TextUtils.truncate_horizontal(text, width)
        return text

    @staticmethod
    def color(text: str, color: Callable[[str], str] | None) -> str:
        if color is None:
            return text

        text = "\n".join([color(m) for m in text.split("\n")])
        return text

    @staticmethod
    def pad_to_itself(text: str):
        text_h = TextUtils.height(text)
        text_w = TextUtils.width(text)
        return TextUtils.pad_to_box(text, text_w, text_h)

    @staticmethod
    def pad_to_box(text: str,
                   width: int,
                   height: int,
                   fillchar: str = " ",
                   offset_x: int = None,
                   offset_y: int = None,
                   top: int = None,
                   left: int = None,
                   right: int = None,
                   bottom: int = None) -> str:
        text_h = TextUtils.height(text)
        # text = "\n".join([term.ljust(line, width, fillchar) for line in text.split("\n")])
        text = "\n".join([TextUtils.justify_left(line, width, fillchar) for line in text.split("\n")])
        if height > text_h:
            text.removesuffix("\n")
            remaining_lines_count = height - text_h
            text += ("\n" + width * " ") * remaining_lines_count
        return text

    @staticmethod
    def wrap_in_border(text: str,
                       vertical_char="│",
                       horizontal_char="─",
                       top_left_char="╭",
                       top_right_char="╮",
                       bottom_left_char="╰",
                       bottom_right_char="╯"):
        text = TextUtils.pad_to_itself(text)
        text_w = TextUtils.width(text)
        lines = text.split("\n")
        border_top = top_left_char + horizontal_char * text_w + top_right_char
        for i in range(len(lines)):
            lines[i] = vertical_char + lines[i] + vertical_char
        border_bottom = bottom_left_char + horizontal_char * text_w + bottom_right_char
        bordered = border_top + "\n" + "\n".join(lines) + "\n" + border_bottom
        return bordered


class KeyboardListener:
    """Provides a way to capture key presses in terminal."""
    _term: Terminal
    _on_press_callback: Callable[[Keystroke], None]

    _timeout: float = 0.01
    _last_key_presses: Dict[str, float] = {}
    _same_key_interval: float = 0.1

    def __init__(self, term: Terminal, on_key_callback: Callable[[Keystroke], None], same_key_interval: float = 0.1):
        stop_event = threading.Event()
        stop_event.clear()
        self._stop_event = stop_event

        self._term = term
        self._on_press_callback = on_key_callback
        self._same_key_interval = same_key_interval

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


class ScreenResizeListener:
    refresh_interval: float
    debug_display: bool
    _term: Terminal
    _callback: Callable

    _last_width: int
    _last_height: int

    def __init__(self, term: Terminal, callback: Callable, refresh_interval: float = 0.001, debug_display: bool = False):
        """
        Executes the given callback every time the terminal screen gets resized.
        The callback if fired only once the terminal has stopped being resized to prevent spamming invocations.

        Args:
            term: Terminal.
            callback: Callback to execute.
            refresh_interval: Interval between screen size checks (in seconds).
            debug_display: Whether to display current dimensions of the terminal window in its top left corner (for debugging).
        """
        stop_event = threading.Event()
        stop_event.clear()
        self._stop_event = stop_event

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
                self._callback()

            self._last_width = width
            self._last_height = height

            if self.debug_display:
                with term.location(0, 0):
                    print_no_newline(term.black_on_pink(f" Terminal size: {width}x{height} "))

            time.sleep(self.refresh_interval)

    def stop(self):
        self._stop_event.set()


class Drawable:
    _is_enabled: bool = True

    _is_force_redrawing: bool = False
    _debug: bool = False
    _draw_count: int = 0

    @property
    def enabled(self) -> bool: return self._is_enabled

    @enabled.setter
    def enabled(self, new_value: bool) -> None:
        self._is_enabled = new_value
        self._on_is_enabled_changed(new_value)

    def _on_is_enabled_changed(self, new_value: bool):
        pass

    def redraw(self) -> None:
        if self.enabled:
            self._redraw_implementation()
            self._draw_count += 1
            self._is_force_redrawing = False

    def force_redraw(self) -> None:
        self._is_force_redrawing = True
        self.redraw()

    def _redraw_child(self, child_drawable: Drawable) -> None:
        child_drawable._is_force_redrawing = self._is_force_redrawing
        child_drawable.redraw()

    def _redraw_implementation(self) -> None:
        pass


class DrawableRect(Drawable):
    pos_x: int = 0
    pos_y: int = 0
    max_height: int = None
    max_width: int = None

    _term: Terminal

    def __init__(self, term: Terminal):
        """
        Defines a rectangular area in the terminal.

        Args:
            term: Terminal object.
        """
        Drawable.__init__(self)

        self._term = term

    @property
    def height(self) -> int:
        if not self.enabled:
            return 0

        max_height = self.max_height
        pos_y = self.pos_y
        term_height = self._term.height
        if (max_height is None) or (max_height <= 0) or (max_height > term_height - pos_y):
            return term_height - pos_y
        else:
            return max_height

    @property
    def width(self) -> int:
        if not self.enabled:
            return 0

        max_width = self.max_width
        pos_x = self.pos_x
        term_width = self._term.width
        if (max_width is None) or (max_width <= 0) or (max_width > term_width - pos_x):
            return term_width - pos_x
        else:
            return max_width

    @property
    def position(self) -> (int, int):
        return self.top_left_corner

    @property
    def top_left_corner(self) -> (int, int):
        return self.pos_x, self.pos_y

    @property
    def bottom_left_corner(self) -> (int, int):
        return self.pos_x, self.pos_y + self.height - 1


class Window(DrawableRect):
    has_borders: bool = False
    background_color: Callable[[str], str] = None

    _term: Terminal
    _content_update_callback: Callable[[Window], None]
    _change_callback: Callable[[], Any] = None

    _change_check_value: Any = None

    _content_buffer: str = ""
    _last_drawn_buffer: str = ""

    _debug_content_buffer: str = ""

    def __init__(self, term: Terminal, content_update_callback: Callable[[Window], None], change_callback: Callable[[], Any] = None):
        """
        Defines a square area in the terminal which can be drawn to.

        Args:
            term: Terminal object.
            content_update_callback: Function which will handle adding updating the content of the pad when it gets drawn
            change_callback: Optional callback which return value will be used to check if redraw_callback() should be called.
                On every call to redraw(), the return value of change_callback() will be checked. If it has not changed since
                the last redraw(), the window will print the cached content.
        """
        DrawableRect.__init__(self, term)

        self._term = term
        self._content_update_callback = content_update_callback
        self._change_callback = change_callback

    @property
    def width_for_content(self):
        if not self.enabled:
            return 0

        width = self.width
        if self.has_borders:
            width -= 2
        width = max(width, 0)
        return width

    @property
    def height_for_content(self):
        if not self.enabled:
            return 0

        height = self.height
        if self.has_borders:
            height -= 2
        height = max(height, 0)
        return height

    def clear_content(self):
        self._content_buffer = ""

    def set_content(self, string: str):
        self._content_buffer = string

    def add_content(self, string: str):
        string = TextUtils.pad_to_itself(string)
        if len(self._content_buffer) > 0:
            self._content_buffer += "\n"
        self._content_buffer += string

    def center_content(self):
        self._content_buffer = TextUtils.center(self._content_buffer, self.width_for_content)

    def _clear_debug_conent(self):
        self._debug_content_buffer = ""

    def _set_debug_conent(self, string: str):
        self._debug_content_buffer = string

    def _check_should_update_content(self) -> bool:
        if self._change_callback is None:
            return True

        value = self._change_callback()
        if self._change_check_value != value:
            self._change_check_value = value
            return True

        return False

    def _redraw_implementation(self) -> None:
        term = self._term

        # debug
        start_time = time.perf_counter()

        # compute content dimensions
        width = self.width_for_content
        height = self.height_for_content

        start = time.perf_counter()

        if not self._is_force_redrawing and not self._check_should_update_content():
            return

        duration = time.perf_counter() - start

        # invoke draw callback to update the content
        self._content_update_callback(self)

        # crop content to fit in window
        content = self._content_buffer
        content = TextUtils.truncate_to_box(content, width, height)
        content = TextUtils.pad_to_box(content, width, height)
        if self.has_borders:
            content = TextUtils.wrap_in_border(content)
        if self.background_color is not None:
            content = self.background_color(content)

        self._last_drawn_buffer = content

        with term.location(self.pos_x, self.pos_y):
            print_no_newline(self._last_drawn_buffer)


        # debug
        redraw_duration = time.perf_counter() - start_time
        if self._debug:
            draw_indicator = "|" if (self._draw_count % 2 == 1) else "─"
            was_forced = " FORCED" if self._is_force_redrawing else ""
            debug_string = term.black_on_pink(f" Window: {self.width}x{self.height} at {self.position}, {redraw_duration * 1000:.1f} ms {draw_indicator}{was_forced} ")
            with term.location(*self.position):
                print_no_newline(debug_string)

            self._clear_debug_conent()
            self._set_debug_conent(f"ho {duration * 1000:.1f} ms")
            if self._debug_content_buffer:
                debug_string = term.black_on_pink(f" Debug: {self._debug_content_buffer} ")
                debug_string = TextUtils.truncate_to_box(debug_string, self.width, 1)
                with term.location(self.pos_x + self.width - 1 - term.length(debug_string), self.pos_y + self.height - 1):
                    print_no_newline(debug_string)


class DrawableRectStack(DrawableRect):
    _rects: List[DrawableRect] = []

    def __init__(self, term: Terminal, rects: List[DrawableRect]):
        """
        Defines a vertical stack of several DrawableRects which automatically controls their dimensions and draws them.
        """
        DrawableRect.__init__(self, term)

        self._rects = rects

    def _on_is_enabled_changed(self, new_value: bool):
        for rect in self._rects:
            rect.enabled = new_value

    def _redraw_implementation(self):
        term = self._term

        # debug
        start_time = time.perf_counter()
        for rect in self._rects:
            rect._debug = self._debug

        # use only enabled rects
        enabled_rects = [x for x in self._rects if x.enabled]

        # calculate minimum height required by child rects
        height = self.height
        used_height = 0
        unconstrained_rects_indices = []
        for i, rect in enumerate(enabled_rects):
            if rect.max_height is None:
                unconstrained_rects_indices.append(i)
                continue
            used_height += rect.max_height

        # calculate height left for unconstrained child rects
        flexible_height = max(height - used_height, 0)
        unconstrained_rects_count = len(unconstrained_rects_indices)
        height_per_unconstrained_rect = math.floor(flexible_height / unconstrained_rects_count) if unconstrained_rects_count > 0 else 0

        # apply max_height to every unconstrained rect
        for i in unconstrained_rects_indices:
            enabled_rects[i].max_height = height_per_unconstrained_rect

        # update positions
        pos_y = self.pos_y
        for i, rect in enumerate(enabled_rects):
            rect.pos_x = self.pos_x
            rect.pos_y = pos_y
            pos_y += rect.height

        # limit max width
        for i, rect in enumerate(enabled_rects):
            rect.max_width = self.width

        # render
        for i, rect in enumerate(enabled_rects):
            self._redraw_child(rect)

        # restore unconstrained rects max_heights
        for i in unconstrained_rects_indices:
            self._rects[i].max_height = None

        # debug
        redraw_duration = time.perf_counter() - start_time
        if self._debug:
            string = term.black_on_purple(f" ") + "\n"

            string += term.black_on_purple(f" Stack: {len(self._rects)} rects, {len(enabled_rects)} active, {redraw_duration*1000:.0f} ms ")

            for i, rect in enumerate(self._rects):
                string += "\n"
                color = term.black_on_purple if rect.enabled else term.gray70_on_purple
                string += term.black_on_purple(color(f"   ({i}) {rect.pos_y:>3} {rect.max_height} "))

            # string = TextUtils.pad_to_itself(string)
            string += "".join([f"\n{term.black_on_purple(' ')}" for _ in range(self.height - len(self._rects) - 2)])

            with term.location(*self.position):
                print_no_newline(string)
