import math

from rich import box
from rich.align import Align
from rich.console import RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual.reactive import Reactive
from textual.widget import Widget

from utils.supervisor import AttackSupervisorState
from utils.tui.definitions.styles import Styles
from utils.tui.menus.shared_menu_utils import SharedMenuUtils


class DetailsMenu(Widget):
    connectivities_per_page: int = Reactive(4)

    def render(self) -> RenderableType:
        self.recalculate_connectivities_per_page()

        items = [
            self.get_attack_table(),
            self.get_connectivity_table(),
            self.get_connectivities_pagination_text(),
        ]

        grid = Table.grid()

        for item in items:
            grid.add_row(Align(item, align="center"))

        return Align(grid, align="center")

    # MESSAGE HANDLERS

    def handle_supervisor_state_updated(self) -> None:
        self.refresh()

    def handle_selected_attack_index_updated(self) -> None:
        self.refresh()

    def handle_selected_connectivity_page_index_updated(self) -> None:
        self.refresh()

    # CONTENT

    def recalculate_connectivities_per_page(self) -> None:
        height = self.size.height

        attack_table_height = 7
        connectivity_text_height = 4
        connectivity_header_height = 3
        height_per_connectivity_row = 3
        pagination_height = 1
        bottom_bar_height = 4

        height_for_connectivities = height - attack_table_height - connectivity_text_height - pagination_height - connectivity_header_height - bottom_bar_height
        max_connectivities_to_fit = math.floor(height_for_connectivities / height_per_connectivity_row)
        max_connectivities_to_fit = max(1, max_connectivities_to_fit)

        self.connectivities_per_page = max_connectivities_to_fit

    def get_attack_table(self) -> Text | Table | Panel:

        text = Text()
        supervisor_state = self.supervisor_state

        if supervisor_state is None:
            text.append("Waiting for supervisor to initialize...")
            return Panel(text, style=Styles.waiting, expand=False, box=box.SQUARE)
        elif not self.app.is_attacks_info_available:
            text.append("Waiting for attack processes to start...")
            return Panel(text, style=Styles.waiting, expand=False, box=box.SQUARE)
        elif (self.selected_attack_index < 0) or (self.selected_attack_index >= self.supervisor_state.attack_processes_count):
            text.append(f"Invalid attack index selected: {self.selected_attack_index}.\nCannot display attack details.")
            return Panel(text, style=Styles.bad, expand=False, box=box.SQUARE)
        else:
            table = Table(box=box.ROUNDED)

            SharedMenuUtils.add_header_to_attack_state_table(table)

            attack = self.supervisor_state.attack_states[self.selected_attack_index]
            SharedMenuUtils.add_attack_row_to_attack_state_table(table, attack)

            return table

    def get_connectivity_table(self) -> Text | Table | Panel:
        if self.supervisor_state is None:
            return Text()
        if self.selected_attack_index >= len(self.supervisor_state.attack_states):
            return Text()

        attack = self.supervisor_state.attack_states[self.selected_attack_index]

        if attack.connectivity_state is None:
            return Panel(Text("Waiting for connectivity check results to arrive..."), style=Styles.waiting, box=box.SQUARE, expand=False)
        else:
            table = Table(box=box.ROUNDED)

            SharedMenuUtils.add_header_to_connectivity_table(table, attack.target)

            SharedMenuUtils.add_rows_to_connectivity_table(table,
                                                           attack,
                                                           self.supervisor_state.proxies_addresses,
                                                           self.selected_connectivity_page_index,
                                                           self.connectivities_per_page)

            return table

    def get_connectivities_pagination_text(self) -> Text:
        if not self.app.is_attacks_info_available:
            return Text()

        attack = self.supervisor_state.attack_states[self.selected_attack_index]
        if not attack.connectivity_state:
            return Text()

        n_connectivities = attack.connectivity_state.total_states
        text = SharedMenuUtils.get_pagination_text(self.selected_connectivity_page_index, self.connectivities_per_page, n_connectivities)

        return text

    # PROPERTIES

    @property
    def supervisor_state(self) -> AttackSupervisorState:
        return self.app.supervisor_state

    @property
    def selected_menu_index(self) -> int:
        return self.app.selected_menu_index

    @property
    def selected_attack_index(self) -> int:
        return self.app.selected_attack_index

    @property
    def selected_connectivity_page_index(self) -> int:
        return self.app.selected_connectivity_page_index
