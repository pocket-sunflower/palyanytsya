from multiprocessing import Queue
from typing import List

from textual import events
from textual.app import App
from textual.message import Message
from textual.message_pump import MessagePump
from textual.reactive import Reactive
from textual.widget import Widget
from textual.widgets import Placeholder

from MHDDoS.utils.misc import get_last_from_queue
from utils.input_args import Arguments
from utils.supervisor import AttackSupervisor, AttackSupervisorState
from utils.tui.events import SupervisorStateUpdated, TestFire
from utils.tui.flair import Flair
from utils.tui.status_bar import StatusBar


class PalyanytsyaApp(App):
    """The Palyanytsya Application"""

    config: Arguments
    supervisor: AttackSupervisor
    supervisor_state_queue: Queue
    supervisor_state = Reactive(None)

    supervisor_state_listeners: List[Widget] = []

    async def on_load(self, event: events.Load) -> None:
        """Bind keys with the app loads (but before entering application mode)"""
        await self.bind("q", "quit", "Quit")

        logging_queue = Queue()
        attacks_state_queue = Queue()
        self.supervisor_state_queue = Queue()
        self.supervisor = AttackSupervisor(PalyanytsyaApp.config, attacks_state_queue, self.supervisor_state_queue, logging_queue)
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

        status_bar = StatusBar()

        self.supervisor_state_listeners = [
            status_bar
        ]

        await self.view.dock(Flair(), edge="top", size=12)
        await self.view.dock(status_bar, edge="top", size=3)
        await self.view.dock(*top_group, edge="top", size=10)
        await self.view.dock(*bottom_group, edge="bottom", size=2)

    async def shutdown(self):
        self.supervisor.stop()
        await App.shutdown(self)

    async def update_supervisor_state(self):
        self.supervisor_state = get_last_from_queue(self.supervisor_state_queue, self.supervisor_state)
        self.log("got update")

    async def watch_supervisor_state(self, supervisor_state: AttackSupervisorState | None) -> None:
        self.log(f"sup state updated")
        message = SupervisorStateUpdated(self)
        message.new_state = supervisor_state

        for listener in self.supervisor_state_listeners:
            listener.refresh()

    def handle_supervisor_state_updated(self, message: SupervisorStateUpdated) -> None:
        self.log(f"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: {message}")

    def handle_test_fire(self, message: TestFire) -> None:
        self.log("hhhhhhhhhhhhhhhhhhhhhhhh")


def run_tui(args: Arguments):
    PalyanytsyaApp.config = args
    PalyanytsyaApp.run(title="Palyanytsya TUI", log="logs/palyanytsya_tui.log")
