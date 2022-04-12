import math
import time
from multiprocessing import Queue
from threading import Thread
from typing import Callable

from blessed import Terminal
from blessed.keyboard import Keystroke
from prettytable import PrettyTable, ALL

from MHDDoS.methods.tools import Tools
from MHDDoS.start import AttackState
from MHDDoS.utils.misc import get_last_from_queue
from utils.blessed_utils import BlessedWindow, center_text, print_and_flush, ScreenResizeHandler, pad_text_to_itself, text_width, pad_text_to_box, KeyboardListener, wrap_text_in_border
from utils.input_args import Arguments
from utils.logs import get_logger_for_current_process
from utils.misc import TimeInterval
from utils.supervisor import AttackSupervisorState

term = Terminal()


def get_flair_string(t: Terminal = None):
    if t is None:
        t = Terminal()
    heart = t.red("♥")
    flair_string = "\n" + \
                   t.green(f"A heavy-duty freedom-infused MHDDoS wrapper...\n") + \
                   "\n" + \
                   t.blue("██████╗░░█████╗░██╗░░░░░██╗░░░██╗░█████╗░███╗░░██╗██╗░░░██╗████████╗░██████╗██╗░░░██╗░█████╗░\n") + \
                   t.blue("██╔══██╗██╔══██╗██║░░░░░╚██╗░██╔╝██╔══██╗████╗░██║╚██╗░██╔╝╚══██╔══╝██╔════╝╚██╗░██╔╝██╔══██╗\n") + \
                   t.blue("██████╔╝███████║██║░░░░░░╚████╔╝░███████║██╔██╗██║░╚████╔╝░░░░██║░░░╚█████╗░░╚████╔╝░███████║\n") + \
                   t.gold("██╔═══╝░██╔══██║██║░░░░░░░╚██╔╝░░██╔══██║██║╚████║░░╚██╔╝░░░░░██║░░░░╚═══██╗░░╚██╔╝░░██╔══██║\n") + \
                   t.gold("██║░░░░░██║░░██║███████╗░░░██║░░░██║░░██║██║░╚███║░░░██║░░░░░░██║░░░██████╔╝░░░██║░░░██║░░██║\n") + \
                   t.gold("╚═╝░░░░░╚═╝░░╚═╝╚══════╝░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚══╝░░░╚═╝░░░░░░╚═╝░░░╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝\n") + \
                   "\n" + \
                   t.green(f"                                                                  ...from Ukraine with love {heart}")
    return flair_string


# MAIN GUI THREAD
class GUI(Thread):
    """GUI thread of Palyanytsya."""
    _update_interval: float = 0.01
    _flair_update_interval: TimeInterval = TimeInterval(100)
    _ui_update_interval: TimeInterval = TimeInterval(0.2)
    _supervisor_state: AttackSupervisorState = None

    _flair_window: BlessedWindow
    _supervisor_window: BlessedWindow
    _attacks_window: BlessedWindow
    _target_status_window: BlessedWindow
    _nav_tips_window: BlessedWindow

    _ui_drawing_time = 0

    # INTERACTIONS
    _keyboard_listener: KeyboardListener
    _selected_attack_index: int | None = 0
    _is_in_target_status_view: bool = False

    SUPERVISOR_HEIGHT = 1
    FLAIR_HEIGHT = 12

    _attacks_table = PrettyTable(
        hrules=ALL,
        header=False,
        left_padding_width=1,
        right_padding_width=1,
        vertical_char="│",
        horizontal_char="─",
        junction_char="┼",
        top_junction_char="┬",
        bottom_junction_char="┴",
        left_junction_char="├",
        right_junction_char="┤",
        top_left_junction_char="╭",
        top_right_junction_char="╮",
        bottom_left_junction_char="╰",
        bottom_right_junction_char="╯",
    )

    def __init__(self,
                 args: Arguments,
                 attacks_state_queue: Queue,
                 supervisor_state_queue: Queue,
                 logging_queue: Queue):
        Thread.__init__(self, daemon=True, name="GUI")

        global logger
        logger = get_logger_for_current_process(logging_queue, "GUI")
        self._logging_queue = logging_queue

        self._args = args
        self._attacks_state_queue = attacks_state_queue
        self._supervisor_state_queue = supervisor_state_queue
        # self._update_interval = update_interval

        # INTERACTIONS

        self._keyboard_listener = KeyboardListener(term, on_key_callback=self._process_keystroke)

        # WINDOWS

        self._flair_window = BlessedWindow(term)
        self._flair_window.max_height = self.FLAIR_HEIGHT

        self._supervisor_window = BlessedWindow(term)
        self._supervisor_window.max_height = self.SUPERVISOR_HEIGHT
        self._supervisor_window.pos_y = self.FLAIR_HEIGHT

        self._target_status_window = BlessedWindow(term)
        self._target_status_window.pos_y = self.FLAIR_HEIGHT + self.SUPERVISOR_HEIGHT

        self._attacks_window = BlessedWindow(term)
        self._attacks_window.pos_y = self.FLAIR_HEIGHT + self.SUPERVISOR_HEIGHT

        self._nav_tips_window = BlessedWindow(term)
        # self._nav_tips_window.background_color = term.black_on_orange
        self._nav_tips_window.max_height = 1
        self._nav_tips_window.pos_y = term.height - 2

    def run(self):
        with term.fullscreen(), term.cbreak(), term.hidden_cursor():
            try:
                print_and_flush(term.home + term.clear)
                ScreenResizeHandler(term, self.force_redraw, debug_display=False)

                while True:
                    self._update_supervisor_state()
                    self.redraw()
                    time.sleep(self._update_interval)
            except (Exception, KeyboardInterrupt, SystemExit) as e:
                print_and_flush(term.clear)
                print_and_flush(pad_text_to_box("", term.width, term.height, term))
                print_and_flush(term.black_on_red(e))
                raise e

    def _update_supervisor_state(self):
        new_state = get_last_from_queue(self._supervisor_state_queue)
        if new_state is not None:
            self._supervisor_state = new_state

    # PROPERTIES

    @property
    def _is_attacks_info_available(self) -> bool:
        if self._supervisor_state is None:
            return False
        if self._supervisor_state.attack_states is None:
            return False
        return True

    @property
    def _is_in_attacks_view(self) -> bool:
        return not self._is_in_target_status_view

    # DRAWING METHODS

    def force_redraw(self):
        self._flair_update_interval.reset()
        self._ui_update_interval.reset()
        self.redraw()

    def redraw(self):
        # if self._flair_update_interval.check_if_has_passed():
        start = time.perf_counter()

        self._draw_flair()
        self._draw_supervisor()

        if self._is_in_target_status_view:
            self._draw_target_status()
        else:
            self._draw_attacks()

        self._draw_nav_tips()

        drawing_time = time.perf_counter() - start
        if drawing_time > 0.001:
            self._ui_drawing_time = drawing_time
        time_sting = f" GUI: {1 / self._ui_drawing_time:>1.1f} FPS "
        time_sting = term.black_on_green(time_sting)
        width = term.length(time_sting)
        with term.location(term.width - width, term.height):
            print_and_flush(term.rjust(time_sting, width))

        # if self._ui_update_interval.check_if_has_passed():

        with term.location(0, term.height):
            print_and_flush(term.black_on_red(f" {self._is_in_target_status_view} "))

        term.move_xy(term.width, term.height)

    def _draw_flair(self):
        gradient = ["█", "▓", "▒", "░", " "]

        flair_window = self._flair_window

        flair_text = get_flair_string(term)
        flair_text_width = text_width(flair_text, term)
        flair_text = pad_text_to_box(flair_text, flair_text_width, flair_window.height, term)

        gradient_steps_count = len(gradient)
        non_flair_text_width = flair_window.width - flair_text_width
        left_side_width = int(math.floor(non_flair_text_width / 2))
        right_side_width = int(math.ceil(non_flair_text_width / 2))
        step = int(right_side_width / gradient_steps_count)
        left_side_extra_width = left_side_width - step * gradient_steps_count
        right_side_extra_width = right_side_width - step * gradient_steps_count

        def craft_flair_side(left_to_right: bool, color: Callable):
            g_list = gradient.copy()
            if not left_to_right:
                g_list.reverse()

            s = ""
            if left_to_right:
                for k in range(left_side_extra_width):
                    s += g_list[0]
            for j in range(gradient_steps_count):
                for k in range(step):
                    s += g_list[j]
            if not left_to_right:
                for k in range(right_side_extra_width):
                    s += g_list[-1]
            s = color(s)
            return s

        flair = []
        flair_text_split = flair_text.split("\n")
        flair_height = len(flair_text_split)
        for i in range(flair_window.height):
            color = term.blue if (i < flair_height // 2) else term.gold
            line = craft_flair_side(True, color)
            line += flair_text_split[i]
            line += craft_flair_side(False, color)
            flair.append(line)
        flair = "\n".join(flair)

        flair = center_text(flair, term)
        flair_window.clear_content()
        flair_window.add_content(flair)
        flair_window.redraw()

    def _draw_supervisor(self):
        supervisor = self._supervisor_state
        s = ""
        # s += "Attack supervisor: "
        if supervisor is None:
            s += "Initializing..."
        else:
            if supervisor.is_fetching_configuration:
                s += "Fetching targets configuration..."
            elif supervisor.is_fetching_proxies:
                s += "Fetching proxies configuration..."
            else:
                s += f"{supervisor.attack_processes_count} attack processes running."

        s = s.upper()
        s = term.center(s, self._supervisor_window.width)
        s = term.black_on_gold(s)
        self._supervisor_window.set_content(s)
        self._supervisor_window.redraw()

    def _draw_attacks(self):
        attacks_table = self._attacks_table
        attacks_table.clear()

        s = ""

        if self._supervisor_state is None:
            s = "Waiting for supervisor to initialize..."
            s = wrap_text_in_border(s, term)
        elif not self._is_attacks_info_available:
            s = "Waiting for attack processes to start..."
            s = wrap_text_in_border(s, term)
        else:
            self._add_header_to_attack_state_table(attacks_table)

            for attack in self._supervisor_state.attack_states:
                self._add_attack_row_to_attack_state_table(attacks_table, attack)

            table_string: str = attacks_table.get_string()
            table_string = self.color_table_header(attacks_table, table_string)
            table_string = self._highlight_table_row(self._selected_attack_index, attacks_table, table_string)

            s += table_string

        # self._attacks_window.max_height = term.height - self.FLAIR_HEIGHT
        s = pad_text_to_itself(s, term)
        s = center_text(s, term)
        self._attacks_window.set_content(s)
        self._attacks_window.redraw()

    def _draw_target_status(self):
        if self._supervisor_state is None:
            return

        if self._selected_attack_index > len(self._supervisor_state.attack_states) - 1:
            self._is_in_target_status_view = False
            return

        attack_state = self._supervisor_state.attack_states[self._selected_attack_index]

        window = self._target_status_window

        window.clear_content()

        s = ""

        s += f"{attack_state.target}"

        window.set_content(s)
        window.center_content()
        window.redraw()

    def _draw_nav_tips(self):

        window = self._nav_tips_window

        color = term.white_on_black
        up = color("UP")
        down = color("DOWN")
        left = color("LEFT")
        right = color("RIGHT")

        s = f"Navigation: {down} = next attack, {up} = previous attack, {left} = all attacks, {right} = selected attack details"
        s = f" {s} "

        window.set_content(s)
        window.center_content()
        window.redraw()

    # ATTACKS TABLE METHODS

    def _add_header_to_attack_state_table(self, table: PrettyTable) -> None:
        attacks_table_columns = [
            # "*",
            "\nTarget",
            "\nMethods",
            "\nTarget\nStatus",
            "\nRequests/s\n(total)",
            "\nBytes/s\n(total)",
            "\nProxies",
            "\nPID",
            "\nThreads",
        ]
        table.add_row(attacks_table_columns)

    def _add_attack_row_to_attack_state_table(self, table: PrettyTable, attack: AttackState) -> None:
        # target status
        target_status = "unknown"

        # methods
        if attack.attack_methods is None:
            attack_methods_string = term.grey("Validating...")
        elif len(attack.attack_methods) == 0:
            attack_methods_string = term.red("0 (no valid \n"
                                             "methods found)")
        else:
            attack_methods_string = "\n".join([term.cyan(m) for m in attack.attack_methods])

        # requests
        rps = f"{Tools.humanformat(attack.requests_per_second)} r/s"
        if attack.requests_per_second == 0:
            rps = term.red(rps)
            # TODO: display change arrow
        requests_string = f"{rps}\n" \
                          f"({Tools.humanformat(attack.total_requests_sent)})"

        # bytes
        bps = f"{Tools.humanbytes(attack.bytes_per_second)}/s"
        if attack.bytes_per_second == 0:
            bps = term.red(rps)
            # TODO: display change arrow
        bytes_string = f"{bps}\n" \
                       f"({Tools.humanbytes(attack.total_bytes_sent)})"

        # proxies
        proxies = ""
        proxies_count = self._supervisor_state.proxies_count
        if attack.proxy_validation_state is not None:
            n_validated_proxies = len(attack.proxy_validation_state.validated_proxies_indices)
            proxies += f"{n_validated_proxies} / {proxies_count}"

            is_validating = not attack.proxy_validation_state.is_validation_complete
            if is_validating:
                progress = attack.proxy_validation_state.progress
                proxies += f"Validating ({progress:.0f}%)..."
            else:
                proxies += f"{n_validated_proxies} valid."
        else:
            if proxies_count > 0:
                proxies = f"{proxies_count}\nValidating..."
            else:
                proxies = term.orange("Not used")

        row_entries = [
            # " > ",
            attack.target,
            attack_methods_string,
            target_status,
            requests_string,
            bytes_string,
            proxies,
            attack.attack_pid,
            attack.active_threads_count,
        ]

        table.add_row(row_entries)

        # empty = ""
        # row_entries = [
        #     # " > ",
        #     empty,
        #     empty,
        #     empty,
        #     requests,
        #     bytes,
        #     empty,
        #     empty,
        #     empty,
        # ]
        #
        # table.add_row(row_entries)

        # s = self._craft_table_row(self.ATTACK_TABLE_SPACING, table_values, "left")
        #
        #
        #     # s += column_name
        #
        # return s

    # TARGET STATUS VIEW

    @staticmethod
    def color_table_header(table: PrettyTable,
                           table_string: str,
                           color: Callable[[str], str] = term.black_on_orange) -> str:
        split = table_string.split("\n")
        header_line = split[1]
        for i in range(1, 4):
            header_split = split[i]
            columns_split = header_split[1:-1].split(table.vertical_char)
            new_row = ""
            colored_vertical_char = term.orange(table.vertical_char)
            new_row += colored_vertical_char
            for j in range(len(columns_split)):
                columns_split[j] = color(columns_split[j])
            new_row += colored_vertical_char.join(columns_split)
            new_row += colored_vertical_char
            split[i] = new_row
        table_string = "\n".join(split)

        return table_string

    @staticmethod
    def _highlight_table_row(row_index: int,
                             table: PrettyTable,
                             table_string: str,
                             color: Callable[[str], str] = term.black_on_bright_white) -> str:
        rows_count = len(table.rows) - 1  # <- account for header row
        if (row_index < 0) or (row_index >= rows_count):
            return table_string

        left_junction_char = table.left_junction_char
        vertical_char = table.vertical_char

        row_strings = table_string.split(left_junction_char)
        for i in range(rows_count):
            i = i + 1  # <- account for header row
            if row_index == (i - 1):
                row_lines = row_strings[i].split("\n")
                for j in range(1, len(row_lines) - 1):
                    line = row_lines[j]
                    line = line[1:]
                    line = line[:-1]
                    line = color(line)
                    row_lines[j] = f"{vertical_char}{line}{vertical_char}"
                row_strings[i] = "\n".join(row_lines)
                break

        table_string = f"{table.left_junction_char}".join(row_strings)

        return table_string

    # INTERACTIONS METHODS

    def _process_keystroke(self, key: Keystroke):
        if key is None:
            return

        if key.is_sequence:
            if self._is_attacks_info_available:
                if key.code == term.KEY_UP:
                    self._select_previous_attack()
                if key.code == term.KEY_DOWN:
                    self._select_next_attack()
                if key.code == term.KEY_RIGHT:
                    self._is_in_target_status_view = True
                if key.code == term.KEY_LEFT:
                    self._is_in_target_status_view = False

    def _select_next_attack(self):
        if not self._is_attacks_info_available:
            return

        self._selected_attack_index += 1
        if self._selected_attack_index > len(self._supervisor_state.attack_states) - 1:
            self._selected_attack_index = 0

    def _select_previous_attack(self):

        self._selected_attack_index -= 1
        if self._selected_attack_index < 0:
            self._selected_attack_index = len(self._supervisor_state.attack_states) - 1
