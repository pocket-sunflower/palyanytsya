import math
import time
from multiprocessing import Queue
from threading import Thread
from typing import Callable

from blessed import Terminal
from blessed.keyboard import Keystroke
from icmplib import Host
from prettytable import PrettyTable, ALL
from requests import Response, RequestException

from MHDDoS.attack import AttackState
from MHDDoS.methods.tools import Tools
from MHDDoS.utils.connectivity import Connectivity, ConnectivityState
from MHDDoS.utils.misc import get_last_from_queue
from MHDDoS.utils.targets import Target
from utils.blessed_utils import BlessedWindow, print_and_flush, ScreenResizeHandler, text_width, pad_text_to_box, KeyboardListener, wrap_text_in_border, color_text
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
    MAX_GUI_WIDTH = 150

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

        window = BlessedWindow(term)
        window.max_height = self.FLAIR_HEIGHT
        window.max_width = self.MAX_GUI_WIDTH
        self._flair_window = window

        window = BlessedWindow(term)
        window.pos_y = self.FLAIR_HEIGHT
        window.max_height = self.SUPERVISOR_HEIGHT
        window.max_width = self.MAX_GUI_WIDTH
        self._supervisor_window = window

        window = BlessedWindow(term)
        window.pos_y = self.FLAIR_HEIGHT + self.SUPERVISOR_HEIGHT
        window.max_width = self.MAX_GUI_WIDTH
        self._attacks_window = window

        window = BlessedWindow(term)
        window.pos_y = self.FLAIR_HEIGHT + self.SUPERVISOR_HEIGHT
        window.max_width = self.MAX_GUI_WIDTH
        self._target_status_window = window

        window = BlessedWindow(term)
        window.pos_y = term.height - 2
        window.max_height = 1
        window.max_width = self.MAX_GUI_WIDTH
        self._nav_tips_window = window

    def run(self):
        with term.fullscreen(), term.cbreak(), term.hidden_cursor():
            try:
                print_and_flush(term.home + term.clear)
                ScreenResizeHandler(term, self.force_redraw, debug_display=False)

                while True:
                    self._update_supervisor_state()
                    self.redraw()
                    time.sleep(self._update_interval)
            except Exception as e:
                # print_and_flush(term.clear)
                # print_and_flush(pad_text_to_box("", term.width, term.height, term))
                term.move_xy(term.width, term.height)
                print_and_flush("\n")
                # print_and_flush(term.black_on_red(e))
                raise e
            except (KeyboardInterrupt, SystemExit):
                pass

    def _update_supervisor_state(self):
        self._supervisor_state = get_last_from_queue(self._supervisor_state_queue, self._supervisor_state)

    # PROPERTIES

    @property
    def _is_attacks_info_available(self) -> bool:
        if self._supervisor_state is None:
            return False
        attack_states = self._supervisor_state.attack_states
        if (attack_states is None) or (len(attack_states) == 0):
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

        # with term.location(0, term.height):
        #     print_and_flush(term.black_on_red(f" {self._is_in_target_status_view} "))

        term.move_xy(term.width, term.height)

    def _draw_flair(self):
        gradient = ["█", "▓", "▒", "░", " "]

        window = self._flair_window
        window.clear_content()

        flair_text = get_flair_string(term)
        flair_text_width = text_width(flair_text, term)
        flair_text = pad_text_to_box(flair_text, flair_text_width, window.height, term)

        gradient_steps_count = len(gradient)
        non_flair_text_width = window.width - flair_text_width
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
        for i in range(window.height):
            color = term.blue if (i < flair_height // 2) else term.gold
            line = craft_flair_side(True, color)
            line += flair_text_split[i]
            line += craft_flair_side(False, color)
            flair.append(line)
        flair = "\n".join(flair)

        window.add_content(flair)
        window.center_content()
        window.redraw()

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

        window = self._attacks_window
        window.clear_content()

        if self._supervisor_state is None:
            s = " Waiting for supervisor to initialize... "
            s = wrap_text_in_border(s, term)
            window.add_content(s)
        elif not self._is_attacks_info_available:
            s = " Waiting for attack processes to start... "
            s = wrap_text_in_border(s, term)
            window.add_content(s)
        else:
            # header
            # header = f"OVERVIEW: {self._supervisor_state.attack_processes_count} ATTACKS RUNNING"
            # header = f" {header} "
            # header = wrap_text_in_border(header, term)
            header = self._get_header()
            window.add_content(header)

            # table
            self._add_header_to_attack_state_table(attacks_table)
            for attack in self._supervisor_state.attack_states:
                self._add_attack_row_to_attack_state_table(attacks_table, attack)
            table_string = attacks_table.get_string()
            table_string = self._color_table_row(0, attacks_table, table_string, term.black_on_orange, term.orange)
            table_string = self._color_table_row(1 + self._selected_attack_index, attacks_table, table_string, None, term.black_on_bright_white)
            window.add_content(table_string)

        window.center_content()
        window.redraw()

    def _get_header(self) -> str:
        inactive_color = term.gray30

        # OVERVIEW HEADER
        header_o = f"OVERVIEW"
        if self._is_in_attacks_view:
            if self._is_attacks_info_available:
                header_o += f": {self._supervisor_state.attack_processes_count} ATTACKS RUNNING"
            else:
                header_o += ": NO ATTACKS RUNNING"
        header_o = f" {header_o} "
        header_o = wrap_text_in_border(header_o, term)
        if not self._is_in_attacks_view:
            header_o = color_text(header_o, inactive_color)

        # DETAILS HEADER
        index = self._selected_attack_index
        header_d = f"DETAILS"
        if self._is_in_target_status_view:
            header_d += f": ATTACK {index + 1}/{self._supervisor_state.attack_processes_count}"
        header_d = f" {header_d} "
        header_d = wrap_text_in_border(header_d, term)
        if not self._is_in_target_status_view:
            header_d = color_text(header_d, inactive_color)

        # JOIN HEADERS
        header_o_split = header_o.split("\n")
        header_d_split = header_d.split("\n")
        header = []
        for i in range(len(header_o_split)):
            header.append(header_o_split[i] + " " + header_d_split[i])
        header = "\n".join(header)

        return header

    def _draw_target_status(self):
        if self._supervisor_state is None:
            return

        if self._selected_attack_index > len(self._supervisor_state.attack_states) - 1:
            self._is_in_target_status_view = False
            return

        attack_state = self._supervisor_state.attack_states[self._selected_attack_index]

        window = self._target_status_window
        window.clear_content()

        # HEADER
        index = self._selected_attack_index
        # header = f" ATTACK DETAILS {index + 1}/{self._supervisor_state.attack_processes_count} "
        # header = wrap_text_in_border(header, term)
        header = self._get_header()
        window.add_content(header)

        # ATTACK INFO
        table = self._attacks_table
        table.clear()
        self._add_header_to_attack_state_table(table)
        self._add_attack_row_to_attack_state_table(table, attack_state)
        table_string = table.get_string()
        table_string = self._color_table_row(0, table, table_string, term.black_on_orange, term.orange)
        window.add_content(table_string)

        # CONNECTIVITY INFO
        table.clear()
        self._add_header_to_connectivity_table(table, attack_state.target)
        self._add_rows_to_connectivity_table(table, attack_state.target)
        table_string = table.get_string()
        table_string = self._color_table_row(0, table, table_string, term.black_on_cyan, term.cyan)
        window.add_content(table_string)

        window.center_content()
        window.redraw()

    def _draw_nav_tips(self):

        window = self._nav_tips_window

        color = term.black_on_yellow
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
            "\nTarget",
            "\nConnectivity",
            "\nMethods",
            "\nProxies",
            "\nRequests/s\n(total)",
            "\nBytes/s\n(total)",
            # "\nPID",
            "\nThreads",
        ]
        table.add_row(attacks_table_columns)

    def _add_attack_row_to_attack_state_table(self, table: PrettyTable, attack: AttackState) -> None:
        # target status
        if attack.has_connectivity_data:
            target_status_string = self._get_concise_target_connectivity_string(attack.target, attack.connectivity_state)
        else:
            target_status_string = "Checking..."  # TODO: set this according to connectivity

        # methods
        if attack.attack_methods is None:
            attack_methods_string = term.webgray("Validating...")
        elif len(attack.attack_methods) == 0:
            attack_methods_string = "0 (no valid \n" \
                                    "methods found)"
            attack_methods_string = color_text(attack_methods_string, term.red)
        else:
            attack_methods_string = "\n".join(attack.attack_methods)
            attack_methods_string = color_text(attack_methods_string, term.cyan)

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
        proxies_string = ""
        proxies_count = self._supervisor_state.proxies_count

        if proxies_count == 0:
            proxies_string = term.webgray("Not used")
        elif attack.proxy_validation_state is None:
            proxies_string = term.webgray(f"Validating...")
        else:
            n_validated_proxies = len(attack.proxy_validation_state.validated_proxies_indices)
            n_used_proxies = attack.used_proxies_count
            n_total_proxies = attack.total_proxies_count
            n_unused_proxies = n_total_proxies - n_used_proxies

            if n_used_proxies > 0:
                proxies_string += f"{term.green(f'{n_used_proxies} valid')}\n"

            if attack.proxy_validation_state.is_validating:
                progress = attack.proxy_validation_state.progress
                proxies_string += f"{term.lightcyan(f'Validating {progress * 100:.0f}%')}"  # TODO: use progress bar instead
            else:
                proxies_string += f"{term.webgray(f'{n_unused_proxies} unused')}"

        row_entries = [
            attack.target,
            target_status_string,
            attack_methods_string,
            proxies_string,
            requests_string,
            bytes_string,
            # attack.attack_pid,
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

    @staticmethod
    def _get_concise_target_connectivity_string(target: Target,
                                                connectivity_state: ConnectivityState) -> str:
        c = Connectivity.UNKNOWN

        if target.is_layer_4:
            c = connectivity_state.connectivity_l4
        elif target.is_layer_7:
            c = connectivity_state.connectivity_l7

        color = GUI._get_term_color_for_connectivity(c)

        if c == Connectivity.UNREACHABLE:
            s = "Unreachable\n(may be down)"
        elif c == Connectivity.UNRESPONSIVE:
            s = "Unresponsive\n(may be down)"
        elif c == Connectivity.PARTIALLY_REACHABLE:
            s = "Partially\nreachable \n(suffering)"
        elif c == Connectivity.REACHABLE:
            s = "Reachable"
        else:
            s = "Unknown"

        s = color_text(s, color)

        return color(s)

    @staticmethod
    def _get_term_color_for_connectivity(c: Connectivity) -> Callable[[str], str]:
        if c == Connectivity.UNKNOWN:
            return term.webgray
        elif c == Connectivity.UNREACHABLE:
            return term.red3
        elif c == Connectivity.UNRESPONSIVE:
            return term.red
        elif c == Connectivity.PARTIALLY_REACHABLE:
            return term.yellow
        elif c == Connectivity.REACHABLE:
            return term.green

        return term.white

    # TARGET STATUS VIEW

    def _add_header_to_connectivity_table(self, table: PrettyTable, target: Target) -> None:
        connectivity_table_columns = [
            "Proxy",
            "Layer 4",  # if target.is_layer_4 else "Layer 7" if target.is_layer_7 else "[INVALID TARGET]"
            "Layer 7"
        ]
        table.add_row(connectivity_table_columns)

    def _add_rows_to_connectivity_table(self, table: PrettyTable, target: Target) -> None:
        attack_state = self._supervisor_state.attack_states[self._selected_attack_index]
        connectivity = attack_state.connectivity_state
        if connectivity is None:
            return

        def get_connectivity_string_l4(layer_4: Host | None) -> str:
            c = Connectivity.get_for_layer_4(layer_4)

            message = ""
            color = term.white

            if c == Connectivity.REACHABLE:
                color = term.green
                message = f"REACHABLE\n" \
                          f"Ping {layer_4.avg_rtt:.0f} ms\n" \
                          f"No packets lost"
            elif Connectivity.PARTIALLY_REACHABLE:
                color = term.yellow
                message = f"PARTIALLY REACHABLE\n" \
                          f"Ping {layer_4.avg_rtt:.0f} ms\n" \
                          f"{layer_4.packet_loss * 100:.0f}% packet loss"
            elif Connectivity.UNREACHABLE:
                color = term.red
                message = color(f"UNREACHABLE")
            elif c == Connectivity.UNKNOWN:
                color = term.webgray
                message = color(f"UNKNOWN")

            message = color_text(message, color)

            return message

        def get_connectivity_string_l7(layer_7: Response | RequestException) -> str:
            c = Connectivity.get_for_layer_7(layer_7)

            message = ""
            color = term.white

            if isinstance(layer_7, Response):
                response: Response = layer_7

                # pick color based on state
                if c == Connectivity.REACHABLE:
                    color = term.green
                elif c == Connectivity.PARTIALLY_REACHABLE:
                    color = term.yellow
                elif c == Connectivity.UNRESPONSIVE:
                    color = term.red

                message = f"Response code {response.status_code}:\n{response.reason}"
            elif isinstance(layer_7, RequestException):
                exception: RequestException = layer_7
                color = term.red
                message = f"Exception:\n{type(exception).__name__}"
            else:
                color = term.webgray
                message = f"UNKNOWN"

            message = color_text(message, color)

            return message

        if not attack_state.is_using_proxies:
            no_proxy_string = color_text(f"DIRECT\n(no proxy)", term.webgray)

            # if target.is_layer_4:
            #     con

            row = [
                no_proxy_string,
                get_connectivity_string_l4(connectivity.layer_4),
                get_connectivity_string_l7(connectivity.layer_7),
            ]
            table.add_row(row)
        else:
            for i in range(len(connectivity.layer_4_proxied)):
                # TODO: display proxy address
                proxy_string = f"Proxy {i + 1}"
                proxy_string = color_text(proxy_string, term.cyan)
                row = [
                    proxy_string,
                    get_connectivity_string_l4(connectivity.layer_4_proxied[i]),
                    get_connectivity_string_l7(connectivity.layer_7_proxied[i]),
                ]
                table.add_row(row)

    # @staticmethod
    # def color_table_header(table: PrettyTable,
    #                        table_string: str,
    #                        color: Callable[[str], str] = term.black_on_orange) -> str:
    #     split = table_string.split("\n")
    #     header_height = len(table_string.split(table.left_junction_char)[0].split("\n"))
    #     for i in range(1, header_height - 1):
    #         header_split = split[i]
    #         columns_split = header_split[1:-1].split(table.vertical_char)
    #         new_row = ""
    #         colored_vertical_char = color(table.vertical_char)
    #         new_row += colored_vertical_char
    #         for j in range(len(columns_split)):
    #             columns_split[j] = color(columns_split[j])
    #         new_row += colored_vertical_char.join(columns_split)
    #         new_row += colored_vertical_char
    #         split[i] = new_row
    #     table_string = "\n".join(split)
    #
    #     return table_string

    @staticmethod
    def _color_table_row(row_index: int,
                         table: PrettyTable,
                         table_string: str,
                         cells_color: Callable[[str], str] = None,
                         lines_color: Callable[[str], str] = None) -> str:
        rows_count = len(table.rows)
        if (row_index < 0) or (row_index >= rows_count):
            return table_string

        left_junction_char = table.left_junction_char
        vertical_char = table.vertical_char
        colored_vertical_char = lines_color(vertical_char) if lines_color else vertical_char

        row_strings = table_string.split(left_junction_char)
        for i in range(rows_count):
            if row_index == i:
                row_lines = row_strings[i].split("\n")
                for j in range(1, len(row_lines) - 1):
                    line = row_lines[j]

                    colored_row_line = ""
                    colored_row_line += colored_vertical_char

                    columns_split = line[1:-1].split(table.vertical_char)
                    if cells_color:
                        for k in range(len(columns_split)):
                            columns_split[k] = cells_color(columns_split[k])

                    colored_row_line += colored_vertical_char.join(columns_split)
                    colored_row_line += colored_vertical_char

                    row_lines[j] = colored_row_line
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
