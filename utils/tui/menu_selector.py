from typing import List, Callable

from rich.align import Align
from rich.console import RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual.widget import Widget

from utils.supervisor import AttackSupervisorState
from utils.tui.definitions.styles import Styles


class MenuSelector(Widget):

    def __init__(self, menus: List[Widget]):
        Widget.__init__(self)

        self.menus: List[Widget] = menus

        self.menu_item_builders: List[Callable[[bool], Text]] = [
            self.get_overview_menu_header,
            self.get_details_menu_header,
        ]

    def render(self) -> RenderableType:
        self.update_menu_visibility()

        menu_tabs = []
        for i, item_builder in enumerate(self.menu_item_builders):
            is_selected = i == self.selected_menu_index

            tab = item_builder(is_selected)
            tab.overflow = "ellipsis"
            tab.no_wrap = True
            tab = Panel(tab, style=Styles.selected if is_selected else Styles.muted)

            menu_tabs.append(tab)

        grid = Table.grid(expand=False)
        grid.add_row(*menu_tabs)

        grid.show_header = False
        grid.overflow = "crop"
        grid.no_wrap = True

        return Align(grid, align="center")

    # MESSAGE HANDLERS

    def handle_supervisor_state_updated(self) -> None:
        self.refresh()

    def handle_selected_menu_index_updated(self) -> None:
        self.refresh()

    def handle_selected_attack_index_updated(self) -> None:
        self.refresh()

    # LOGIC

    def update_menu_visibility(self):
        for i, menu in enumerate(self.menus):
            menu.visible = (i == self.selected_menu_index)

    # CONTENT

    def get_overview_menu_header(self, is_selected: bool) -> Text:
        supervisor_state = self.supervisor_state
        if supervisor_state is None:
            return Text("...")

        text = Text(f"OVERVIEW")
        if is_selected:
            if self.app.is_attacks_info_available:
                n_attacks = supervisor_state.attack_processes_count
                attacks = "ATTACKS" if (n_attacks > 1) else "ATTACK"
                text += f": {supervisor_state.attack_processes_count} {attacks} RUNNING"
            else:
                text += ": NO ATTACKS RUNNING"

        return text

    def get_details_menu_header(self, is_selected: bool) -> Text:
        supervisor_state = self.supervisor_state
        if supervisor_state is None:
            return Text("...")

        index = self.selected_attack_index
        text = Text(f"DETAILS")
        if is_selected:
            text += f": ATTACK {index + 1}/{supervisor_state.attack_processes_count}"

        return text

    # PROPERTIES

    @property
    def n_menus(self) -> int:
        return len(self.menu_item_builders)

    @property
    def is_in_overview_menu(self) -> bool:
        return self.selected_menu_index == 0

    @property
    def is_in_details_menu(self) -> bool:
        return self.selected_menu_index == 1

    @property
    def supervisor_state(self) -> AttackSupervisorState:
        return self.app.supervisor_state

    @property
    def selected_attack_index(self) -> int:
        return self.app.selected_attack_index

    @property
    def selected_menu_index(self) -> int:
        return self.app.selected_menu_index
