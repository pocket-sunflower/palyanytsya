import math
import threading
import time
import traceback
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
from utils.blessed_utils import Window, print_no_newline, KeyboardListener, TextUtils, DrawableRectStack, Drawable, ScreenResizeListener
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


class Pagination:
    """
    Collection of helper functions to help with paginating tables.
    """

    @staticmethod
    def get_total_pages(items_per_page: int, total_items: int):
        total_pages = math.ceil(total_items / items_per_page)
        return total_pages

    @staticmethod
    def get_page_index(item_index: int, items_per_page: int, total_items: int) -> int:
        total_pages = math.ceil(total_items / items_per_page)
        page_index = math.floor(item_index / items_per_page)

        last_page_index = total_pages - 1
        if page_index > last_page_index:
            return last_page_index

        return page_index

    @staticmethod
    def get_page_bounds(page_index: int, items_per_page: int, total_items: int) -> (int, int):
        total_pages = math.ceil(total_items / items_per_page)
        last_page_index = total_pages - 1
        if page_index > last_page_index:
            page_index = last_page_index

        page_start_index = page_index * items_per_page

        if page_index == last_page_index:
            page_end_index = total_items
        else:
            page_end_index = page_start_index + items_per_page

        return page_start_index, page_end_index

    @staticmethod
    def get_item_index_on_page(item_index: int, items_per_page: int) -> int:
        item_index_on_page = item_index % items_per_page
        return item_index_on_page


# MAIN GUI THREAD
class GUI(Thread, Drawable):
    """GUI thread of Palyanytsya."""
    _update_interval: float = 1
    _flair_update_interval: TimeInterval = TimeInterval(100)
    # _ui_update_interval: TimeInterval = TimeInterval(1.2)
    _supervisor_state: AttackSupervisorState = None

    # _flair_window: Window
    # _supervisor_window: Window
    # _attacks_window: Window
    # _target_status_window: Window
    # _nav_tips_window: Window
    _gui_stack: DrawableRectStack

    _ui_drawing_time = 0

    # INTERACTIONS
    _keyboard_listener: KeyboardListener
    _selected_attack_index: int = 0
    _connectivity_page_index: int = 0

    SUPERVISOR_HEIGHT = 1
    FLAIR_HEIGHT = 12
    MAX_GUI_WIDTH = 300
    ATTACKS_PER_PAGE = 5
    ATTACKS_TABLE_HEADER_HEIGHT = 5
    ATTACKS_TABLE_ROW_HEIGHT = 3
    CONNECTIVITIES_TABLE_HEADER_HEIGHT = 3
    CONNECTIVITIES_TABLE_ROW_HEIGHT = 4
    CONNECTIVITIES_PER_PAGE = 4

    _table = PrettyTable(
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

    _redraw_lock = threading.Lock()

    def __init__(self,
                 args: Arguments,
                 attacks_state_queue: Queue,
                 supervisor_state_queue: Queue,
                 logging_queue: Queue):
        Thread.__init__(self, daemon=True, name="GUI")

        self.logger = get_logger_for_current_process(logging_queue, "GUI")
        self._logging_queue = logging_queue

        self._args = args
        self._attacks_state_queue = attacks_state_queue
        self._supervisor_state_queue = supervisor_state_queue
        # self._update_interval = update_interval

        stop_event = threading.Event()
        stop_event.clear()
        self._stop_event = stop_event

        # ASSEMBLE THE GUI

        all_gui_elements = []

        spacer = Window(term, lambda _: None)

        flair_window = Window(
            term,
            content_update_callback=self._draw_flair,
            change_callback=lambda: self._flair_update_interval.check_if_has_passed()
        )
        flair_window.max_height = self.FLAIR_HEIGHT
        all_gui_elements.append(flair_window)

        supervisor_window = Window(
            term,
            content_update_callback=self._draw_supervisor,
            change_callback=lambda: self._supervisor_state
        )
        supervisor_window.max_height = self.SUPERVISOR_HEIGHT
        all_gui_elements.append(supervisor_window)

        header_window = Window(
            term,
            content_update_callback=self._draw_header,
            change_callback=lambda: (
                self._is_in_target_status_view,
                self._supervisor_state)
        )
        header_window.max_height = 3
        all_gui_elements.append(header_window)

        attacks_window = Window(
            term,
            content_update_callback=self._draw_attacks,
            change_callback=lambda: (
                self._supervisor_state.attack_states if self._supervisor_state else []
            )
        )
        attacks_window.max_height = self.ATTACKS_TABLE_HEADER_HEIGHT + self.ATTACKS_TABLE_ROW_HEIGHT * self.ATTACKS_PER_PAGE
        attacks_pagination_window = Window(
            term,
            content_update_callback=self._draw_attacks_pagination,
            change_callback=lambda: (
                self._supervisor_state.attack_states if self._supervisor_state else [],
                self._selected_attack_index
            )
        )
        self._attacks_view = DrawableRectStack(
            term,
            rects=[
                attacks_window,
                attacks_pagination_window,
                # spacer
            ]
        )
        all_gui_elements.append(self._attacks_view)

        target_status_window = Window(
            term,
            content_update_callback=self._draw_target_status,
            change_callback=lambda: (
                self._supervisor_state.attack_states if self._supervisor_state else [],
                self._selected_attack_index
            )
        )
        target_status_window.max_height = self.ATTACKS_TABLE_HEADER_HEIGHT + self.ATTACKS_TABLE_ROW_HEIGHT
        connectivity_window = Window(
            term,
            content_update_callback=self._draw_target_connectivity,
            change_callback=lambda: (
                self._supervisor_state.attack_states if self._supervisor_state else [],
                self._selected_attack_index,
            )
        )
        connectivity_window.max_height = self.CONNECTIVITIES_TABLE_HEADER_HEIGHT + self.CONNECTIVITIES_TABLE_ROW_HEIGHT * self.CONNECTIVITIES_PER_PAGE
        connectivity_pagination_window = Window(
            term,
            content_update_callback=self._draw_target_connectivity_pagination,
            change_callback=lambda: (
                self._supervisor_state.attack_states if self._supervisor_state else [],
                self._selected_attack_index,
                self._connectivity_page_index
            )
        )
        self._target_status_view = DrawableRectStack(
            term,
            rects=[
                target_status_window,
                connectivity_window,
                connectivity_pagination_window,
                # spacer
            ]
        )
        self._target_status_view.enabled = False
        all_gui_elements.append(self._target_status_view)

        nav_tips_window = Window(
            term,
            content_update_callback=self._draw_nav_tips,
            change_callback=lambda: self._is_in_target_status_view
        )
        nav_tips_window.max_height = 1
        all_gui_elements.append(nav_tips_window)

        self._gui_stack = DrawableRectStack(
            term,
            rects=all_gui_elements
        )
        self._gui_stack.max_width = self.MAX_GUI_WIDTH
        self._gui_stack._debug = True

        # INTERACTIONS

        self._keyboard_listener = KeyboardListener(term, on_key_callback=self._process_keystroke)
        self._screen_resize_listener = ScreenResizeListener(term, callback=self._handle_screen_resize, debug_display=False)

    def run(self):
        try:
            with term.fullscreen(), term.cbreak(), term.hidden_cursor():
                print_no_newline(term.home + term.clear)

                while not self._stop_event.is_set():
                    self._update_supervisor_state()

                    with self._redraw_lock:
                        self.redraw()

                    time.sleep(self._update_interval)
        except Exception as e:
            print_no_newline(term.clear)
            print_no_newline(term.black_on_red(" Exception in GUI thread: \n\n"))
            trace = traceback.format_exc()
            print_no_newline(term.red(trace))
            # print_and_flush(TextUtils.pad_to_box("", term.width, term.height))
            # with term.location(term.width, term.height):
            # print_and_flush(term.black_on_red(e))
            # while True:
            #     print_and_flush(term.black_on_red("hello"))
            #     time.sleep(0.5)
            raise SystemExit
        except (KeyboardInterrupt, SystemExit) as e:
            # raise e
            pass
        finally:
            # print_and_flush("\n")
            # self._keyboard_listener.stop()
            self.logger.info("GUI thread exited.")

    def stop(self):
        self._stop_event.set()

    def _update_supervisor_state(self):
        self._supervisor_state = get_last_from_queue(self._supervisor_state_queue, self._supervisor_state)

    def _handle_screen_resize(self):
        with self._redraw_lock:
            self._is_force_redrawing = True

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
    def _is_in_target_status_view(self) -> bool:
        return self._target_status_view.enabled

    @property
    def _is_in_attacks_view(self) -> bool:
        return self._attacks_view.enabled

    # DRAWING METHODS

    def _redraw_implementation(self):
        # if self._flair_update_interval.check_if_has_passed():
        start = time.perf_counter()

        self._redraw_child(self._gui_stack)

        drawing_time = time.perf_counter() - start
        self._ui_drawing_time = max(drawing_time, 0.001)
        time_sting = f" GUI: {1 / self._ui_drawing_time:>3.1f} FPS "
        time_sting = term.black_on_green(time_sting)
        width = term.length(time_sting)
        with term.location(term.width - width, term.height):
            print_no_newline(term.rjust(time_sting, width))

        # if self._ui_update_interval.check_if_has_passed():

        # with term.location(0, term.height):
        #     print_and_flush(term.black_on_red(f" {self._is_in_target_status_view} "))

        term.move_xy(term.width, term.height)

    # DRAWING CALLBACKS

    def _draw_flair(self, window: Window):
        gradient = ["█", "▓", "▒", "░", " "]

        window.clear_content()

        flair_text = get_flair_string(term)
        flair_text_width = TextUtils.width(flair_text)
        flair_text = TextUtils.pad_to_box(flair_text, flair_text_width, window.height)

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

    def _draw_supervisor(self, window: Window):
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
        s = term.center(s, window.width)
        s = term.black_on_gold(s)
        window.set_content(s)

    def _draw_header(self, window: Window):
        window.clear_content()

        inactive_color = term.gray30

        # OVERVIEW HEADER
        header_o = f"OVERVIEW"
        if self._is_in_attacks_view:
            if self._is_attacks_info_available:
                header_o += f": {self._supervisor_state.attack_processes_count} ATTACKS RUNNING"
            else:
                header_o += ": NO ATTACKS RUNNING"
        header_o = f" {header_o} "
        header_o = TextUtils.wrap_in_border(header_o)
        if not self._is_in_attacks_view:
            header_o = TextUtils.color(header_o, inactive_color)

        # DETAILS HEADER
        index = self._selected_attack_index
        header_d = f"DETAILS"
        if self._is_in_target_status_view:
            header_d += f": ATTACK {index + 1}/{self._supervisor_state.attack_processes_count}"
        header_d = f" {header_d} "
        header_d = TextUtils.wrap_in_border(header_d)
        if not self._is_in_target_status_view:
            header_d = TextUtils.color(header_d, inactive_color)

        # JOIN HEADERS
        header_o_split = header_o.split("\n")
        header_d_split = header_d.split("\n")
        header = []
        for i in range(len(header_o_split)):
            header.append(header_o_split[i] + " " + header_d_split[i])
        header = "\n".join(header)

        window.add_content(header)
        window.center_content()

    def _draw_attacks(self, window: Window):
        window.clear_content()

        attacks_table = self._table
        attacks_table.clear()

        if self._supervisor_state is None:
            s = " Waiting for supervisor to initialize... "
            s = TextUtils.wrap_in_border(s)
            window.add_content(s)
        elif not self._is_attacks_info_available:
            s = " Waiting for attack processes to start... "
            s = TextUtils.wrap_in_border(s)
            window.add_content(s)
        else:
            # table
            self._add_header_to_attack_state_table(attacks_table)

            attacks = self._supervisor_state.attack_states
            n_attacks = len(attacks)
            n_attack_pages = math.ceil(n_attacks / self.ATTACKS_PER_PAGE)

            page_index = Pagination.get_page_index(self._selected_attack_index, self.ATTACKS_PER_PAGE, n_attacks)
            start_index, stop_index = Pagination.get_page_bounds(page_index, self.ATTACKS_PER_PAGE, n_attacks)

            for attack in attacks[start_index:stop_index]:
                self._add_attack_row_to_attack_state_table(attacks_table, attack)

            table_string = attacks_table.get_string()
            table_string = self._color_table_row(0, attacks_table, table_string, term.black_on_orange, term.orange)
            selected_attack_index_on_page = Pagination.get_item_index_on_page(self._selected_attack_index, self.ATTACKS_PER_PAGE)
            table_string = self._color_table_row(1 + selected_attack_index_on_page, attacks_table, table_string, term.black_on_bright_white, term.black_on_bright_white)
            window.add_content(table_string)

        window.center_content()

    def _draw_attacks_pagination(self, window: Window):
        window.clear_content()

        if not self._is_attacks_info_available:
            return

        attacks = self._supervisor_state.attack_states
        n_attacks = len(attacks)
        page_index = Pagination.get_page_index(self._selected_attack_index, self.ATTACKS_PER_PAGE, n_attacks)
        pagination_text = self.get_pagination_string(page_index, self.ATTACKS_PER_PAGE, n_attacks)

        window.set_content(pagination_text)
        window.center_content()

    def _draw_target_status(self, window: Window):
        window.clear_content()

        if self._supervisor_state is None:
            return
        if self._selected_attack_index > len(self._supervisor_state.attack_states) - 1:
            window.enabled = False
            return

        attack_state = self._supervisor_state.attack_states[self._selected_attack_index]

        # ATTACK INFO
        table = self._table
        table.clear()
        self._add_header_to_attack_state_table(table)
        self._add_attack_row_to_attack_state_table(table, attack_state)
        table_string = table.get_string()
        table_string = self._color_table_row(0, table, table_string, term.black_on_orange, term.orange)
        window.add_content(table_string)

        # CONNECTIVITY INFO

        window.center_content()

    def _draw_target_connectivity(self, window: Window):
        window.clear_content()

        if self._supervisor_state is None:
            return
        if self._selected_attack_index > len(self._supervisor_state.attack_states) - 1:
            return

        table = self._table
        attack_state = self._supervisor_state.attack_states[self._selected_attack_index]

        if attack_state.connectivity_state is None:
            tip = "Waiting for connectivity check results to arrive..."
            window.add_content(tip)
        else:
            table.clear()
            self._add_header_to_connectivity_table(table, attack_state.target)
            self._add_rows_to_connectivity_table(table, attack_state.target)
            table_string = table.get_string()
            table_string = self._color_table_row(0, table, table_string, term.black_on_cyan, term.cyan)
            window.add_content(table_string)

        window.center_content()

    def _draw_target_connectivity_pagination(self, window: Window):
        window.clear_content()

        if not self._is_attacks_info_available:
            return

        connectivity = self._supervisor_state.attack_states[self._selected_attack_index].connectivity_state
        if connectivity is None:
            return

        n_connectivities = max(connectivity.total_proxies_count, 1)
        pagination_text = self.get_pagination_string(self._connectivity_page_index, self.CONNECTIVITIES_PER_PAGE, n_connectivities)

        window.add_content(pagination_text)
        window.center_content()



    def _draw_nav_tips(self, window: Window):
        color = term.black_on_yellow
        up = color("UP")
        down = color("DOWN")
        left = color("LEFT")
        right = color("RIGHT")

        s = f"Navigation: {down} = next attack, {up} = previous attack, {left} = all attacks, {right} = selected attack details"
        s = f" {s} "

        window.set_content(s)
        window.center_content()

    @staticmethod
    def get_pagination_string(page_index: int, items_per_page: int, total_items: int) -> str:
        page_number = page_index + 1
        total_pages = Pagination.get_total_pages(items_per_page, total_items)

        string = f"PAGE {page_number}/{total_pages}"

        if page_number == 1:
            string = f"{string} ▼"
        elif page_number == total_pages:
            string = f"▲ {string}"
        else:
            string = f"▲ {string} ▼"

        return string

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
            target_status_string = term.webgray("Checking...")

        # methods
        if attack.attack_methods is None:
            attack_methods_string = term.webgray("Validating...")
        elif len(attack.attack_methods) == 0:
            attack_methods_string = "0 (no valid \n" \
                                    "methods found)"
            attack_methods_string = TextUtils.color(attack_methods_string, term.red)
        else:
            n_attack_methods = len(attack.attack_methods)
            first_two = attack.attack_methods[0:2] if (n_attack_methods > 1) else attack.attack_methods
            if n_attack_methods > 2:
                first = attack.attack_methods[0]
                attack_methods_string = f"{first}\n(+{n_attack_methods - 1} more)"
            else:
                attack_methods_string = "\n".join(first_two)

            attack_methods_string = TextUtils.color(attack_methods_string, term.cyan)

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
        n_proxies_total = self._supervisor_state.proxies_count

        if n_proxies_total == 0:
            proxies_string = term.webgray("Not used")
        else:
            n_validated_proxies = attack.connectivity_state.valid_proxies_count if attack.connectivity_state else 0
            n_proxies_used = attack.used_proxies_count
            n_proxies_total = attack.total_proxies_count
            n_proxies_ignored = n_proxies_total - n_proxies_used

            if n_proxies_used > 0:
                if attack.connectivity_state and attack.connectivity_state.has_valid_proxies:
                    proxies_string += f"{term.green(f'{n_proxies_used} used')}\n"
                else:
                    proxies_string += f"{n_proxies_used} used\n"
            else:
                proxies_string += f"{term.red(f'None used')}\n"

            # if n_proxies_ignored:
            #     proxies_string += f"{term.webgray(f'{n_proxies_ignored} ignored')}"

            proxies_string += f"{term.webgray(f'from {n_proxies_total}')}"

            # if attack.proxy_validation_state.is_validating:
            #     progress = attack.proxy_validation_state.progress
            #     proxies_string += f"{term.lightcyan(f'Validating {progress * 100:.0f}%')}"  # TODO: use progress bar instead
            # else:

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
            s = "Reachable\n"
            s += f"(through {connectivity_state.valid_proxies_count} proxies)"
        else:
            s = "Unknown"

        s = TextUtils.color(s, color)

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
        layer_string = "Layer 4" if target.is_layer_4 else "Layer 7" if target.is_layer_7 else "[INVALID TARGET]"
        connectivity_table_columns = [
            "Proxy",
            layer_string
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

            message = TextUtils.color(message, color)

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

            message = TextUtils.color(message, color)

            return message

        def get_connectivity_string(layer_4: Host | None, layer_7: Response | RequestException) -> str:
            if target.is_layer_4:
                return get_connectivity_string_l4(layer_4)
            if target.is_layer_7:
                return get_connectivity_string_l7(layer_7)
            return term.webgray("UNKNOWN")

        if not attack_state.is_using_proxies:
            no_proxy_string = TextUtils.color(f"DIRECT\n(no proxy)", term.webgray)

            # if target.is_layer_4:
            #     con

            row = [
                no_proxy_string,
                get_connectivity_string(connectivity.layer_4, connectivity.layer_7),
            ]
            table.add_row(row)
        else:
            n_connectivities = max(connectivity.total_proxies_count, 1)
            start_index, stop_index = Pagination.get_page_bounds(self._connectivity_page_index, self.CONNECTIVITIES_PER_PAGE, n_connectivities)
            if target.is_layer_4:
                for i, layer_4 in enumerate(connectivity.layer_4_proxied[start_index:stop_index]):
                    # TODO: display proxy address
                    proxy_string = f"Proxy {i + 1}"
                    proxy_string = TextUtils.color(proxy_string, term.cyan)
                    row = [
                        proxy_string,
                        get_connectivity_string_l4(layer_4)
                    ]
                    table.add_row(row)
            if target.is_layer_7:
                for i, layer_7 in enumerate(connectivity.layer_7_proxied[start_index:stop_index]):
                    # TODO: display proxy address
                    proxy_string = f"Proxy {i + 1}"
                    proxy_string = TextUtils.color(proxy_string, term.cyan)
                    row = [
                        proxy_string,
                        get_connectivity_string_l7(layer_7)
                    ]
                    table.add_row(row)

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
                    self._switch_to_target_status_view()
                if key.code == term.KEY_LEFT:
                    self._switch_to_attacks_view()

    def _switch_to_attacks_view(self):
        self._attacks_view.enabled = True
        self._target_status_view.enabled = False

    def _switch_to_target_status_view(self):
        self._attacks_view.enabled = False
        self._target_status_view.enabled = True

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
