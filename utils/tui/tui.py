import time
from multiprocessing import Queue
from typing import List

from textual import events, messages
from textual.app import App
from textual.message import Message
from textual.message_pump import MessagePump
from textual.reactive import Reactive
from textual.widget import Widget
from textual.widgets import Placeholder

from MHDDoS.utils.misc import get_last_from_queue
from utils.input_args import Arguments
from utils.supervisor import AttackSupervisor, AttackSupervisorState
from utils.tui import messages
from utils.tui.messages import SupervisorStateUpdated, SelectedAttackIndexUpdated, SelectedMenuIndexUpdated
from utils.tui.flair import Flair
from utils.tui.menu_selector import MenuSelector
from utils.tui.status_bar import StatusBar


class PalyanytsyaApp(App):
    """The Palyanytsya Application"""

    config: Arguments
    logging_queue: Queue
    supervisor: AttackSupervisor
    supervisor_state_queue: Queue
    supervisor_state: AttackSupervisorState = Reactive(None)

    selected_attack_index: int = Reactive(0)
    selected_menu_index: int = Reactive(0)

    menu_selector: MenuSelector = None

    is_displaying_popup: bool = Reactive(False)

    async def on_load(self, event: events.Load) -> None:
        """Bind keys with the app loads (but before entering application mode)"""
        await self.bind("q", "quit", "Quit")

        self.supervisor_state_queue = Queue()
        self.supervisor = AttackSupervisor(PalyanytsyaApp.config, self.supervisor_state_queue, PalyanytsyaApp.logging_queue)
        self.supervisor.start()

        self.set_interval(interval=0.5, callback=self.update_supervisor_state)

    async def on_mount(self) -> None:
        """Mount the calculator widget."""

        top_group = (
            Placeholder(name="Statusbar"),
            Placeholder(name="Spacer"),
        )

        bottom_group = (
            Placeholder(name="Navigation", height=1),
            Placeholder(name="Debug", height=1),
        )

        self.menu_selector = MenuSelector()

        await self.view.dock(Flair(), edge="top", size=12)
        await self.view.dock(StatusBar(), edge="top", size=2)
        await self.view.dock(MenuSelector(), edge="top", size=3)
        # await self.view.dock(*top_group, edge="top", size=10)
        await self.view.dock(*bottom_group, edge="bottom", size=2)

    async def shutdown(self):
        # shutdown supervisor
        self.supervisor.stop()
        self.supervisor.join()
        await App.shutdown(self)

    async def update_supervisor_state(self):
        new_state = get_last_from_queue(self.supervisor_state_queue)
        if (new_state is not None) and (new_state != self.supervisor_state):
            self.supervisor_state = new_state

    # EVENT HANDLERS

    async def on_key(self, event: events.Key) -> None:
        self.log(f"key pressed: {event.key}")

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
        if self.supervisor_state.attack_processes_count == 0:
            self.selected_menu_index = 1

        index = min(index, self.menu_selector.n_menus - 1)
        index = max(index, 0)
        self.selected_menu_index = index

    def action_select_next_menu(self):
        self.action_select_menu(self.selected_menu_index + 1)

    def action_select_previous_menu(self):
        self.action_select_menu(self.selected_menu_index - 1)

    def action_select_next_item(self):
        raise NotImplementedError

    def action_select_previous_item(self):
        raise NotImplementedError

    def action_accept_popup(self):
        raise NotImplementedError

    # WATCHERS

    async def watch_supervisor_state(self, new_state: AttackSupervisorState | None) -> None:
        await self._post_message_to_children(messages.SupervisorStateUpdated(self, new_state))

    async def watch_selected_attack_index(self, new_index: int) -> None:
        await self._post_message_to_children(messages.SelectedAttackIndexUpdated(self, new_index))

    async def watch_selected_menu_index(self, new_index: int) -> None:
        await self._post_message_to_children(messages.SelectedMenuIndexUpdated(self, new_index))

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
    def is_in_target_status_view(self) -> bool:
        return self._target_status_view.enabled

    @property
    def is_in_attacks_view(self) -> bool:
        return self._attacks_view.enabled


def run_tui(args: Arguments, logging_queue: Queue):
    PalyanytsyaApp.config = args
    PalyanytsyaApp.logging_queue = logging_queue
    time.sleep(2)
    PalyanytsyaApp.run(title="Palyanytsya TUI", log="logs/palyanytsya_tui.log")
