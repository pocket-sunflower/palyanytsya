import time
from multiprocessing import Queue
from threading import Thread
from typing import List

from blessed import Terminal
from prettytable import PrettyTable, ALL

from MHDDoS.methods.tools import Tools
from MHDDoS.start import AttackState
from MHDDoS.utils.misc import get_last_from_queue
from utils.blessed_utils import BlessedWindow, center_text, print_and_flush, ScreenResizeHandler, pad_text
from utils.input_args import Arguments
from utils.misc import TimeInterval
from utils.supervisor import AttackSupervisorState

term = Terminal()


def get_flair_string(t: Terminal = None):
    if t is None:
        t = Terminal()
    heart = t.red("♥")
    flair_string = "\n" + \
                   "A heavy-duty freedom-infused MHDDoS wrapper...\n" + \
                   "\n" + \
                   t.blue("██████╗░░█████╗░██╗░░░░░██╗░░░██╗░█████╗░███╗░░██╗██╗░░░██╗████████╗░██████╗██╗░░░██╗░█████╗░\n") + \
                   t.blue("██╔══██╗██╔══██╗██║░░░░░╚██╗░██╔╝██╔══██╗████╗░██║╚██╗░██╔╝╚══██╔══╝██╔════╝╚██╗░██╔╝██╔══██╗\n") + \
                   t.blue("██████╔╝███████║██║░░░░░░╚████╔╝░███████║██╔██╗██║░╚████╔╝░░░░██║░░░╚█████╗░░╚████╔╝░███████║\n") + \
                   t.gold("██╔═══╝░██╔══██║██║░░░░░░░╚██╔╝░░██╔══██║██║╚████║░░╚██╔╝░░░░░██║░░░░╚═══██╗░░╚██╔╝░░██╔══██║\n") + \
                   t.gold("██║░░░░░██║░░██║███████╗░░░██║░░░██║░░██║██║░╚███║░░░██║░░░░░░██║░░░██████╔╝░░░██║░░░██║░░██║\n") + \
                   t.gold("╚═╝░░░░░╚═╝░░╚═╝╚══════╝░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚══╝░░░╚═╝░░░░░░╚═╝░░░╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝\n") + \
                   "\n" + \
                   f"                                                                  ...from Ukraine with love {heart}"
    return flair_string


# MAIN GUI THREAD
class GUI(Thread):
    """GUI thread of Palyanytsya."""
    _update_interval: float
    _flair_update_interval: TimeInterval = TimeInterval(1)
    _supervisor_update_interval: TimeInterval = TimeInterval(0.5)
    _attacks_update_interval: TimeInterval = TimeInterval(0.5)
    _supervisor_state: AttackSupervisorState = None

    _flair_window: BlessedWindow
    _supervisor_window: BlessedWindow
    _attacks_window: BlessedWindow

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

    _ui_drawing_time = 0

    SUPERVISOR_HEIGHT = 1
    FLAIR_HEIGHT = 12

    def __init__(self,
                 args: Arguments,
                 attacks_state_queue: Queue,
                 supervisor_state_queue: Queue,
                 update_interval: float = 1):
        Thread.__init__(self, daemon=True, name="GUI")
        self._args = args
        self._attacks_state_queue = attacks_state_queue
        self._supervisor_state_queue = supervisor_state_queue
        self._update_interval = update_interval

        self._flair_window = BlessedWindow(term)
        self._flair_window.max_height = self.FLAIR_HEIGHT

        self._supervisor_window = BlessedWindow(term)
        self._supervisor_window.max_height = self.SUPERVISOR_HEIGHT
        self._supervisor_window.pos_y = self.FLAIR_HEIGHT

        self._attacks_window = BlessedWindow(term)
        self._attacks_window.pos_y = self.FLAIR_HEIGHT + self.SUPERVISOR_HEIGHT

    def run(self):
        try:
            with term.fullscreen(), term.cbreak(), term.hidden_cursor():
                print_and_flush(term.home + term.clear)
                ScreenResizeHandler(term, self.force_redraw, debug_display=False)

                while True:
                    self._update_supervisor_state()
                    self.redraw()
                    time.sleep(self._update_interval)
        except (Exception, KeyboardInterrupt, SystemExit) as e:
            print_and_flush(term.clear)
            raise e

    def _update_supervisor_state(self):
        new_state = get_last_from_queue(self._supervisor_state_queue)
        if new_state is not None:
            self._supervisor_state = new_state

    def force_redraw(self):
        self._flair_update_interval.reset()
        self._supervisor_update_interval.reset()
        self._attacks_update_interval.reset()
        self.redraw()

    def redraw(self):
        start = time.perf_counter()

        self._draw_flair()
        self._draw_supervisor()
        self._draw_attacks()

        self._ui_drawing_time = time.perf_counter() - start
        with term.location(term.width - 40, term.height):
            time_sting = f" Last GUI refresh time: {self._ui_drawing_time * 1000:.0f} ms "
            time_sting = term.black_on_green(time_sting)
            print_and_flush(term.rjust(time_sting, 40))

    def _draw_flair(self):
        if not self._flair_update_interval.check_if_has_passed():
            return

        flair_text = get_flair_string(term)
        flair_text = pad_text(flair_text, term)
        flair_text = center_text(flair_text, term)
        self._flair_window.update_content(flair_text)
        self._flair_window.redraw()

    def _draw_supervisor(self):
        if not self._supervisor_update_interval.check_if_has_passed():
            return

        supervisor = self._supervisor_state
        s = ""
        s += "Attack supervisor: "
        if supervisor is None:
            s += "Initializing..."
        else:
            if supervisor.is_fetching_configuration:
                s += "Fetching targets configuration..."
            elif supervisor.is_fetching_proxies:
                s += "Fetching proxies configuration..."
            else:
                s += f"{supervisor.attack_processes_count} attack processes running."

        s = term.center(s, self._supervisor_window.width)
        s = term.black_on_gold(s)
        self._supervisor_window.update_content(s)
        self._supervisor_window.redraw()

    def _draw_attacks(self):
        if not self._attacks_update_interval.check_if_has_passed():
            return

        attacks_table = self._attacks_table
        attacks_table.clear()

        if self._supervisor_state is None:
            s = "Waiting for supervisor to initialize..."
            attacks_table.add_row([s])
            s = attacks_table.get_string()
        elif self._supervisor_state.attack_processes_count <= 0:
            s = "Waiting for attack processes to start..."
            attacks_table.add_row([s])
            s = attacks_table.get_string()
        else:

            self._attack_state_table_add_header(attacks_table)

            text = ""
            if self._supervisor_state is None:
                text += "Waiting for supervisor to start..."
            elif self._supervisor_state.attack_processes_count <= 0:
                text += "Waiting for attack processes to start..."
            else:
                for attack in self._supervisor_state.attack_states:
                    self._attack_state_table_add_attack_row(attacks_table, attack)

            s: str = attacks_table.get_string()

            # color the header
            split = s.split("\n")
            header_line = split[1]
            for i in range(1, 4):
                header_split = split[i]
                columns_split = header_split[1:-1].split(attacks_table.vertical_char)
                new_row = ""
                colored_vertical_char = term.orange(attacks_table.vertical_char)
                new_row += colored_vertical_char
                for j in range(len(columns_split)):
                    columns_split[j] = term.black_on_orange(columns_split[j])
                new_row += colored_vertical_char.join(columns_split)
                new_row += colored_vertical_char
                split[i] = new_row
            s = "\n".join(split)

        # self._attacks_window.max_height = term.height - self.FLAIR_HEIGHT
        s = pad_text(s, term)
        s = center_text(s, term)
        self._attacks_window.update_content(s)
        self._attacks_window.redraw()

    def _attack_state_table_add_header(self, table: PrettyTable) -> None:
        attacks_table_columns = [
            # "*",
            "\nTarget",
            "\nMethods",
            "\nStatus",
            "\nRequests/s\n(total)",
            "\nBytes/s\n(total)",
            "\nProxies",
            "\nPID",
            "\nThreads",
        ]
        table.add_row(attacks_table_columns)

    def _attack_state_table_add_attack_row(self, table: PrettyTable, attack: AttackState) -> None:
        # methods
        attack_methods = "<TODO>"  # attack.attack_methods

        # requests
        requests = f"{Tools.humanformat(attack.requests_per_second)} r/s\n" \
                   f"({Tools.humanformat(attack.total_requests_sent)})"

        # bytes
        bytes = f"{Tools.humanbytes(attack.bytes_per_second)}/s\n" \
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

        # target status
        target_status = "unknown"

        row_entries = [
            # " > ",
            attack.target,
            attack_methods,
            target_status,
            requests,
            bytes,
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

    def _craft_table_row(self,
                         column_widths: List[int],
                         column_values: List[str],
                         alignment: str = "center",
                         pad: bool = True) -> str:
        if alignment == "center":
            aligner = term.center
        elif alignment == "left":
            aligner = term.ljust
        elif alignment == "right":
            aligner = term.rjust
        else:
            raise ValueError(f"Alignment can be one of (center|left|right). Received '{alignment}'.")

        row = "│"
        for i, width in enumerate(column_widths):
            value = column_values[i] if len(column_values) > i else ""
            if pad:
                value = f" {value} "
            row += term.truncate(aligner(value, width), width)
            row += "│"

        return row
