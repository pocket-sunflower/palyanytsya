import math
import queue
from multiprocessing import Queue

from rich.text import Text
from textual import events, messages
from textual.app import App
from textual.message import Message
from textual.reactive import Reactive

from MHDDoS.utils.misc import get_last_from_queue
from utils.input_args import Arguments
from utils.supervisor import AttackSupervisor, AttackSupervisorState
from utils.tui.definitions import messages
from utils.tui.definitions.layers import Layers
from utils.tui.flair import Flair
from utils.tui.menu_selector import MenuSelector
from utils.tui.menus.details_menu import DetailsMenu
from utils.tui.menus.overview_menu import OverviewMenu
from utils.tui.navigation_bar import NavigationBar
from utils.tui.status_bar import StatusBar


class PalyanytsyaApp(App):
    """The Palyanytsya Application"""

    config: Arguments
    logging_queue: Queue
    supervisor: AttackSupervisor
    supervisor_state_queue: queue.Queue
    supervisor_state: AttackSupervisorState = Reactive(None)

    selected_menu_index: int = Reactive(0)
    selected_attack_index: int = Reactive(0)
    selected_connectivity_page_index: int = Reactive(0)

    menu_selector: MenuSelector = None
    details_menu: DetailsMenu = None

    is_displaying_popup: bool = Reactive(False)

    async def on_load(self, event: events.Load) -> None:
        """Bind keys with the app loads (but before entering application mode)"""
        await self.bind("q", "quit", "Quit")

        self.supervisor_state_queue = queue.Queue()
        self.supervisor = AttackSupervisor(PalyanytsyaApp.config, self.supervisor_state_queue, PalyanytsyaApp.logging_queue)
        self.supervisor.start()

        self.set_interval(interval=0.5, callback=self.update_supervisor_state)

    async def on_mount(self) -> None:
        """Mount the calculator widget."""

        self.details_menu = DetailsMenu()
        self.menu_selector = MenuSelector(
            menus=[
                OverviewMenu(),
                self.details_menu
            ]
        )

        await self.view.dock(Flair(), edge="top", size=12)
        await self.view.dock(StatusBar(), edge="top", size=2)
        await self.view.dock(self.menu_selector, edge="top", size=3)
        for menu in self.menu_selector.menus:
            await self.view.dock(menu, edge="top")

        await self.view.dock(NavigationBar(self.details_menu), edge="bottom", size=1, z=Layers.FOOTER)

    async def shutdown(self):
        # shutdown supervisor
        await App.shutdown(self)
        self.supervisor.stop()
        self.supervisor.join()

    async def update_supervisor_state(self):
        # check if supervisor is healthy
        if not self.supervisor.is_alive():
            raise self.supervisor.exception

        # get new state
        new_state = get_last_from_queue(self.supervisor_state_queue)
        if (new_state is not None) and (new_state != self.supervisor_state):
            self.supervisor_state = new_state

    # EVENT HANDLERS

    async def on_key(self, event: events.Key) -> None:
        self.log(f"key pressed: {event.key}")

        if not self.is_running:
            return

        if self.is_displaying_popup:
            match event.key:
                case "enter":
                    await self.action("accept_popup")

        match event.key:
            case "left":
                await self.action("select_previous_menu")
            case "right":
                await self.action("select_next_menu")
            case "up":
                await self.action("select_previous_item")
            case "down":
                await self.action("select_next_item")

    # ACTIONS

    def action_select_menu(self, index: int = 0):
        if not self.is_supervisor_loaded:
            self.selected_menu_index = 0
            return
        if self.supervisor_state.attack_processes_count == 0:
            self.selected_menu_index = 0
            return

        index = min(index, self.menu_selector.n_menus - 1)
        index = max(index, 0)
        self.selected_menu_index = index

    def action_select_next_menu(self):
        if not self.is_supervisor_loaded:
            self.action_select_menu(0)

        self.action_select_menu(self.selected_menu_index + 1)

    def action_select_previous_menu(self):
        if not self.is_supervisor_loaded:
            self.action_select_menu(0)

        self.action_select_menu(self.selected_menu_index - 1)

    def action_select_next_item(self):
        if self.menu_selector.is_in_overview_menu:
            self.action_select_next_attack()
        elif self.menu_selector.is_in_details_menu:
            self.action_select_next_connectivity_page()

    def action_select_previous_item(self):
        if self.menu_selector.is_in_overview_menu:
            self.action_select_previous_attack()
        elif self.menu_selector.is_in_details_menu:
            self.action_select_previous_connectivity_page()

    def action_accept_popup(self):
        raise NotImplementedError

    def action_select_attack(self, index: int = 0):
        if not self.is_supervisor_loaded:
            self.selected_attack_index = 0
            return
        elif self.supervisor_state.attack_processes_count == 0:
            self.selected_attack_index = 0
            return

        n_selectable_attacks = self.supervisor_state.attack_processes_count

        if index >= n_selectable_attacks:
            index = 0
        elif index < 0:
            index = max(n_selectable_attacks - 1, 0)

        self.selected_attack_index = index

    def action_select_next_attack(self):
        self.action_select_attack(self.selected_attack_index + 1)

    def action_select_previous_attack(self):
        self.action_select_attack(self.selected_attack_index - 1)

    def action_select_connectivity_page(self, index: int = 0):
        if not self.is_supervisor_loaded:
            self.selected_connectivity_page_index = 0
            return

        if self.supervisor_state.attack_processes_count == 0:
            self.selected_connectivity_page_index = 0
            return

        selected_attack = self.supervisor_state.attack_states[self.selected_attack_index]
        if selected_attack.connectivity_state is None:
            self.selected_connectivity_page_index = 0
            return

        n_selectable_connectivties = max(1, selected_attack.connectivity_state.total_proxies_count)

        n_connectivity_pages = math.ceil(n_selectable_connectivties / self.details_menu.connectivities_per_page)

        if index >= n_connectivity_pages:
            index = 0
        elif index < 0:
            index = max(n_connectivity_pages - 1, 0)

        self.selected_connectivity_page_index = index

    def action_select_next_connectivity_page(self):
        self.action_select_connectivity_page(self.selected_connectivity_page_index + 1)

    def action_select_previous_connectivity_page(self):
        self.action_select_connectivity_page(self.selected_connectivity_page_index - 1)

    # WATCHERS

    async def watch_supervisor_state(self, new_state: AttackSupervisorState | None) -> None:
        await self._post_message_to_children(messages.SupervisorStateUpdated(self, new_state))

    async def watch_selected_menu_index(self, new_index: int) -> None:
        await self._post_message_to_children(messages.SelectedMenuIndexUpdated(self, new_index))

    async def watch_selected_attack_index(self, new_index: int) -> None:
        await self._post_message_to_children(messages.SelectedAttackIndexUpdated(self, new_index))

    async def watch_selected_connectivity_page_index(self, new_index: int) -> None:
        await self._post_message_to_children(messages.SelectedConnectivityPageIndexUpdated(self, new_index))

    async def _post_message_to_children(self, message: Message):
        for child in self.children:
            await child.post_message(message)

    # PROPERTIES

    @property
    def last_supervisor_update_time(self) -> float:
        if self.is_supervisor_loaded:
            return self._supervisor_state.timestamp

        return -1

    @property
    def is_supervisor_loaded(self) -> bool:
        if self.supervisor_state is None:
            return False

        return True

    @property
    def is_attacks_info_available(self) -> bool:
        if not self.is_supervisor_loaded:
            return False

        attack_states = self.supervisor_state.attack_states
        if (attack_states is None) or (len(attack_states) == 0):
            return False

        return True

    @property
    def is_in_overview_menu(self) -> bool:
        return self.selected_menu_index == 0

    @property
    def is_in_details_menu(self) -> bool:
        return self.selected_menu_index == 1


def run_tui(args: Arguments, logging_queue: Queue):
    PalyanytsyaApp.config = args
    PalyanytsyaApp.logging_queue = logging_queue
    PalyanytsyaApp.run(title="Palyanytsya TUI", log="logs/palyanytsya_tui.log")
