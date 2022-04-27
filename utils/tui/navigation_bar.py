from typing import Dict

from rich.align import Align
from rich.console import RenderableType
from rich.table import Table
from rich.text import Text
from textual.widget import Widget

from utils.supervisor import AttackSupervisorState
from utils.tui import messages
from utils.tui.menu_selector import MenuSelector
from utils.tui.menus.details_menu import DetailsMenu
from utils.tui.styles import Styles


class NavigationBar(Widget):

    def __init__(self, details_menu: DetailsMenu):
        Widget.__init__(self)
        self.details_menu = details_menu

    def render(self) -> RenderableType:
        bar = self.get_navigation_bar()
        return Align(bar, align="center", vertical="bottom", style=Styles.navigation_bar)

    # MESSAGE HANDLERS

    def handle_supervisor_state_updated(self) -> None:
        self.refresh()

    def handle_selected_attack_index_updated(self) -> None:
        self.refresh()

    def handle_selected_menu_index_updated(self) -> None:
        self.refresh()

    # CONTENT

    def get_navigation_bar(self) -> RenderableType:

        key_mappings = self.get_key_mappings()

        if len(key_mappings) == 0:
            return Text()

        grid = Table.grid(padding=(0, 1))

        # grid.add_column("Navigation: ")

        actions = []
        for (key, action) in key_mappings.items():
            sub_grid = Table.grid()
            sub_grid.add_row(
                Text(f" {key} ", style=Styles.navigation_key, no_wrap=True),
                Text(f" = {action}", no_wrap=True)
            )
            actions.append(sub_grid)

        grid.add_row("Navigation:", *actions)

        return grid

    def get_key_mappings(self) -> Dict[str, str]:
        key_mappings: Dict[str, str] = {}

        if self.is_in_overview_menu:

            if self.is_supervisor_loaded:
                if self.supervisor_state.attack_processes_count > 1:
                    key_mappings["DOWN"] = "select next attack"
                    key_mappings["UP"] = "select previous attack"

            if self.is_attacks_info_available:
                selected_attack_number = self.selected_attack_index + 1
                key_mappings["RIGHT"] = f"show details for attack {selected_attack_number}"

        elif self.is_in_details_menu:

            if self.is_attacks_info_available:
                selected_attack = self.supervisor_state.attack_states[self.selected_attack_index]
                if selected_attack.connectivity_state is not None:
                    connectivities_count = selected_attack.connectivity_state.total_states
                    if connectivities_count > self.details_menu.connectivities_per_page:
                        key_mappings["DOWN"] = "next connectivity page"
                        key_mappings["UP"] = "previous connectivity page"

            key_mappings["LEFT"] = "go back to attacks menu"

        return key_mappings

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
    def is_attacks_info_available(self) -> bool:
        return self.app.is_attacks_info_available

    @property
    def is_supervisor_loaded(self) -> bool:
        return self.app.is_supervisor_loaded

    @property
    def is_in_overview_menu(self) -> bool:
        return self.app.is_in_overview_menu

    @property
    def is_in_details_menu(self) -> bool:
        return self.app.is_in_details_menu
