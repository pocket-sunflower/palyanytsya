import math

from prettytable import PrettyTable, ALL
from rich import box
from rich.align import Align
from rich.console import RenderableType
from rich.panel import Panel
from rich.style import Style
from rich.table import Table
from rich.text import Text
from textual.reactive import Reactive
from textual.widget import Widget

from MHDDoS.attack import AttackState
from MHDDoS.methods.tools import Tools
from MHDDoS.utils.connectivity import Connectivity, ConnectivityState
from MHDDoS.utils.targets import Target
from utils.gui import Pagination
from utils.supervisor import AttackSupervisorState
from utils.tui import messages
from utils.tui.styles import Styles


class OverviewMenu(Widget):
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

    attacks_per_page: int = Reactive(4)

    def render(self) -> RenderableType:
        self.recalculate_attacks_per_page()

        table = self.get_attacks_table()

        pagination = self.get_attacks_pagination_text()

        grid = Table.grid()

        grid.add_row(table)
        grid.add_row(Align(pagination, align="center"))

        return Align(grid, align="center")

    # MESSAGE HANDLERS

    def handle_supervisor_state_updated(self, message: messages.SupervisorStateUpdated) -> None:
        self.refresh()

    def handle_selected_attack_index_updated(self, message: messages.SelectedAttackIndexUpdated) -> None:
        self.refresh()

    # CONTENT

    def recalculate_attacks_per_page(self) -> None:
        height = self.size.height

        header_height = 4
        height_per_attack_row = 3
        pagination_height = 1

        height_for_attacks = height - header_height - pagination_height

        max_attacks_to_fit = math.floor(height_for_attacks / height_per_attack_row)
        max_attacks_to_fit = max(1, max_attacks_to_fit)

        self.attacks_per_page = max_attacks_to_fit

    def get_attacks_table(self) -> Text | Table | Panel:
        text = Text()
        supervisor_state = self.supervisor_state

        if supervisor_state is None:
            text.append("Waiting for supervisor to initialize...")
            return Panel(text, style=Styles.waiting, expand=False)
        elif not self.app.is_attacks_info_available:
            text.append("Waiting for attack processes to start...")
            return Panel(text, style=Styles.waiting, expand=False)
        else:
            attacks_table = self._table
            attacks_table.clear()

            table = Table(box=box.ROUNDED)

            self.add_header_to_attack_state_table(table)

            attacks = self.supervisor_state.attack_states
            n_attacks = len(attacks)

            page_index = Pagination.get_page_index(self.app.selected_attack_index, self.attacks_per_page, n_attacks)
            start_index, stop_index = Pagination.get_page_bounds(page_index, self.attacks_per_page, n_attacks)

            for attack in attacks[start_index:stop_index]:
                self.add_attack_row_to_attack_state_table(table, attack)

            # table_string = self._color_table_row(0, attacks_table, table_string, color_attacks_header, color_attacks_header_alt)
            selected_attack_index_on_page = Pagination.get_item_index_on_page(self.app.selected_attack_index, self.attacks_per_page)
            table.rows[selected_attack_index_on_page].style = Styles.selected
            # table_string = self._color_table_row(1 + selected_attack_index_on_page, attacks_table, table_string, color_selection, color_selection)

            return table

    @staticmethod
    def add_header_to_attack_state_table(table: Table) -> None:
        table.add_column("Target", justify="center", max_width=40)
        table.add_column("Proxies", justify="center")
        table.add_column("Connectivity", justify="center")
        table.add_column("Methods", justify="center")
        table.add_column("Requests/s (total)", justify="center")
        table.add_column("Bytes/s (total)", justify="center")
        table.add_column("Threads", justify="center")

        table.header_style = Styles.attacks_header

    def add_attack_row_to_attack_state_table(self, table: Table, attack: AttackState) -> None:
        # target status
        if attack.has_connectivity_data:
            target_status_string = self.get_concise_target_connectivity_text(attack.target, attack.connectivity_state)
        else:
            target_status_string = Text("Checking...", style=Styles.muted + Styles.waiting)

        # methods
        if attack.attack_methods is None:
            attack_methods_string = Text("Validating...", style=Styles.muted)
        elif len(attack.attack_methods) == 0:
            attack_methods_string = Text("0 (no valid \n"
                                         "methods found)", style=Styles.bad)
        else:
            n_attack_methods = len(attack.attack_methods)
            first_two = attack.attack_methods[0:2] if (n_attack_methods > 1) else attack.attack_methods
            if n_attack_methods > 2:
                first = attack.attack_methods[0]
                attack_methods_string = Text(f"{first}\n(+{n_attack_methods - 1} more)")
            else:
                attack_methods_string = Text("\n".join(first_two))

            attack_methods_string.style = Styles.special

        # requests
        rps = Text(f"{Tools.humanformat(attack.requests_per_second)} r/s")
        if attack.requests_per_second == 0:
            rps.style = Styles.bad
            # TODO: display change arrow
        requests_string = rps + Text(f"\n"
                                     f"({Tools.humanformat(attack.total_requests_sent)})")

        # bytes
        bps = Text(f"{Tools.humanbytes(attack.bytes_per_second)}/s")
        if attack.bytes_per_second == 0:
            bps.style = Styles.bad
            # TODO: display change arrow
        bytes_string = bps + Text(f"\n"
                                  f"({Tools.humanbytes(attack.total_bytes_sent)})")

        # proxies
        proxies_string = Text()
        n_proxies_total = self.supervisor_state.proxies_count

        if n_proxies_total == 0:
            proxies_string = Text("Not used", style=Styles.muted)
        else:
            n_validated_proxies = attack.connectivity_state.valid_proxies_count if attack.connectivity_state else 0
            n_proxies_used = attack.used_proxies_count
            n_proxies_total = attack.total_proxies_count
            n_proxies_ignored = n_proxies_total - n_proxies_used

            if n_proxies_used > 0:
                if attack.connectivity_state and attack.connectivity_state.has_valid_proxies:
                    proxies_string.append(Text(f"{n_proxies_used} used\n", style=Styles.ok))
                else:
                    proxies_string.append(Text(f"{n_proxies_used} used\n"))
            else:
                proxies_string.append(Text(f"None used\n", style=Styles.bad))

            # if n_proxies_ignored:
            #     proxies_string += f"{term.webgray(f'{n_proxies_ignored} ignored')}"

            proxies_string += Text(f"from {n_proxies_total}", style=Styles.muted)

            # if attack.proxy_validation_state.is_validating:
            #     progress = attack.proxy_validation_state.progress
            #     proxies_string += f"{term.lightcyan(f'Validating {progress * 100:.0f}%')}"  # TODO: use progress bar instead
            # else:

        row_entries = [
            str(attack.target),
            proxies_string,
            target_status_string,
            attack_methods_string,
            requests_string,
            bytes_string,
            str(attack.active_threads_count),
        ]

        table.add_row(*row_entries, end_section=True)

    @staticmethod
    def get_concise_target_connectivity_text(target: Target, connectivity_state: ConnectivityState) -> Text:
        c = Connectivity.UNKNOWN

        if target.is_layer_4:
            c = connectivity_state.connectivity_l4
        elif target.is_layer_7:
            c = connectivity_state.connectivity_l7

        style = OverviewMenu.get_style_for_connectivity(c)

        text = Text()

        if c == Connectivity.UNREACHABLE:
            text.append(f"Unreachable\n(may be down)")
        elif c == Connectivity.UNRESPONSIVE:
            text.append("Unresponsive\n(may be down)")
        elif c == Connectivity.PARTIALLY_REACHABLE:
            text.append("Partially\nreachable")
        elif c == Connectivity.REACHABLE:
            text.append(f"Reachable")
            if connectivity_state.uses_proxies:
                if connectivity_state.valid_proxies_count > 1:
                    text.append(f"\n(through {connectivity_state.valid_proxies_count} proxies)")
                else:
                    text.append(f"\n(through {connectivity_state.valid_proxies_count} proxies)")
        else:
            text.append("Unknown")

        text.style = style

        return text

    @staticmethod
    def get_style_for_connectivity(c: Connectivity) -> Style:
        if c == Connectivity.UNKNOWN:
            return Styles.muted
        elif c == Connectivity.UNREACHABLE:
            return Styles.critical
        elif c == Connectivity.UNRESPONSIVE:
            return Styles.bad
        elif c == Connectivity.PARTIALLY_REACHABLE:
            return Styles.warning
        elif c == Connectivity.REACHABLE:
            return Styles.ok

        return Style(color="white")@staticmethod

    @staticmethod
    def get_pagination_text(page_index: int, items_per_page: int, total_items: int) -> Text:
        page_number = page_index + 1
        total_pages = Pagination.get_total_pages(items_per_page, total_items)

        text = Text(f"PAGE {page_number}/{total_pages}")

        if total_pages == 1:
            text = Text()
        elif page_number == 1:
            text = text + Text(" ▼")
        elif page_number == total_pages:
            text = Text("▲ ") + text
        else:
            text = Text("▲ ") + text + Text(" ▼")

        return text

    def get_attacks_pagination_text(self) -> Text:
        if not self.app.is_attacks_info_available:
            return Text()

        attacks = self.supervisor_state.attack_states
        n_attacks = len(attacks)
        page_index = Pagination.get_page_index(self.selected_attack_index, self.attacks_per_page, n_attacks)
        text = self.get_pagination_text(page_index, self.attacks_per_page, n_attacks)

        return text

    # PROPERTIES

    @property
    def supervisor_state(self) -> AttackSupervisorState:
        return self.app.supervisor_state

    @property
    def selected_attack_index(self) -> int:
        return self.app.selected_attack_index

    @property
    def selected_menu_index(self) -> int:
        return self.app.selected_menu_index
