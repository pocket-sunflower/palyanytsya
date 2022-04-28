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
from utils.tui.menus.shared_menu_utils import SharedMenuUtils, Pagination


class OverviewMenu(Widget):
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

    def handle_supervisor_state_updated(self) -> None:
        self.refresh()

    def handle_selected_attack_index_updated(self) -> None:
        self.refresh()

    # CONTENT

    def recalculate_attacks_per_page(self) -> None:
        height = self.size.height

        header_height = 4
        height_per_attack_row = 3
        pagination_height = 1
        bottom_bar_height = 4

        height_for_attacks = height - header_height - pagination_height - bottom_bar_height

        max_attacks_to_fit = math.floor(height_for_attacks / height_per_attack_row)
        max_attacks_to_fit = max(1, max_attacks_to_fit)

        self.attacks_per_page = max_attacks_to_fit

    def get_attacks_table(self) -> Text | Table | Panel:
        text = Text()
        supervisor_state = self.supervisor_state

        if supervisor_state is None:
            text.append("Waiting for supervisor to initialize...")
            return Panel(text, style=Styles.waiting, expand=False, box=box.SQUARE)
        elif not self.app.is_attacks_info_available:
            text.append("Waiting for attack processes to start...")
            return Panel(text, style=Styles.waiting, expand=False, box=box.SQUARE)
        else:
            table = Table(box=box.ROUNDED)

            SharedMenuUtils.add_header_to_attack_state_table(table)

            attacks = self.supervisor_state.attack_states
            n_attacks = len(attacks)

            page_index = Pagination.get_page_index(self.app.selected_attack_index, self.attacks_per_page, n_attacks)
            start_index, stop_index = Pagination.get_page_bounds(page_index, self.attacks_per_page, n_attacks)

            for attack in attacks[start_index:stop_index]:
                SharedMenuUtils.add_attack_row_to_attack_state_table(table, attack)

            selected_attack_index_on_page = Pagination.get_item_index_on_page(self.app.selected_attack_index, self.attacks_per_page)
            table.rows[selected_attack_index_on_page].style = Styles.selected

            return table

    def get_attacks_pagination_text(self) -> Text:
        if not self.app.is_attacks_info_available:
            return Text()

        attacks = self.supervisor_state.attack_states
        n_attacks = len(attacks)
        page_index = Pagination.get_page_index(self.selected_attack_index, self.attacks_per_page, n_attacks)
        text = SharedMenuUtils.get_pagination_text(page_index, self.attacks_per_page, n_attacks)

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
