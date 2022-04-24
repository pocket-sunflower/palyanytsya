from rich.align import Align, AlignMethod
from rich.console import RenderableType, Group
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import Progress
from rich.table import Table
from rich.text import Text
from textual import events
from textual.message import Message
from textual.views import DockView
from textual.widget import Widget

from utils.supervisor import AttackSupervisorState
from utils.tui.events import SupervisorStateUpdated, TestFire
from utils.tui.styles import Styles


class StatusBar(Widget):
    supervisor_state: AttackSupervisorState = None

    def render(self) -> RenderableType:

        self.supervisor_state = self.app.supervisor_state

        grid = Table.grid(expand=True)

        text = self.get_ip_info()
        grid.add_row(Align(text, align="center"), style=Styles.status_bar)

        infos = [
            self.get_targets_info(),
            self.get_proxies_info(),
            self.get_attacks_info(),
        ]
        text = Text(" • ").join(infos)
        grid.add_row(Align(text, align="center"), style=Styles.status_bar)

        # grid.style = Styles.status_bar
        grid.overflow = "crop"
        grid.no_wrap = True

        return grid

    def get_ip_info(self) -> Text:
        if self.supervisor_state is None:
            return Text()

        text = Text()

        local_ip_geolocation = self.supervisor_state.local_ip_geolocation
        if local_ip_geolocation is None:
            text += "Public IP: Checking..."
        else:
            text += f"Public IP: {local_ip_geolocation}"

        if self.supervisor_state.is_fetching_geolocation:
            text += ""

        return text

    def get_targets_info(self) -> Text:
        if self.supervisor_state is None:
            return Text()

        text = Text()

        n_targets = self.supervisor_state.targets_count
        if n_targets == 1:
            text += f"1 target"
        elif n_targets > 1:
            text += f"{n_targets} targets"
        else:
            text += f"No targets"

        if self.supervisor_state.is_fetching_targets:
            text += " (fetching)"

        return text

    def get_proxies_info(self) -> Text:
        if self.supervisor_state is None:
            return Text()

        text = Text()

        n_proxies = self.supervisor_state.proxies_count
        if n_proxies == 1:
            text += f"1 proxy"
        elif n_proxies > 1:
            text += f"{n_proxies} proxies"
        else:
            text += f"No proxies"

        if self.supervisor_state.is_fetching_proxies:
            text += " (fetching)"

        return text

    def get_attacks_info(self) -> Text:
        if self.supervisor_state is None:
            return Text()

        text = Text()

        n_attacks = self.supervisor_state.attack_processes_count
        if n_attacks == 1:
            text += f"1 attack process"
        elif n_attacks > 1:
            text += f"{n_attacks} attack processes"
        else:
            text += f"No attack processes"

        return text
