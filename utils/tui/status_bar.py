from rich.align import Align
from rich.console import RenderableType
from rich.table import Table
from rich.text import Text
from textual.widget import Widget

from utils.supervisor import AttackSupervisorState
from utils.tui.definitions.messages import SupervisorStateUpdated
from utils.tui.definitions.styles import Styles


class StatusBar(Widget):

    def render(self) -> RenderableType:
        grid = Table.grid(expand=True)

        text = self.get_ip_info()
        if not text:
            text = Text(" ")
        text.overflow = "ellipsis"
        text.no_wrap = True
        grid.add_row(Align(text, align="center"), style=Styles.status_bar)

        infos = [
            self.get_targets_info(),
            self.get_proxies_info(),
            self.get_attacks_info(),
        ]
        text = Text(" • ").join(infos)
        text.overflow = "ellipsis"
        text.no_wrap = True
        grid.add_row(Align(text, align="center"), style=Styles.status_bar)

        # grid.style = Styles.status_bar
        grid.overflow = "crop"
        grid.no_wrap = True

        return grid

    def handle_supervisor_state_updated(self, message: SupervisorStateUpdated) -> None:
        self.refresh()

    def get_ip_info(self) -> Text:
        supervisor_state = self.supervisor_state
        if supervisor_state is None:
            return Text()

        text = Text()

        local_ip_geolocation = supervisor_state.local_ip_geolocation
        if local_ip_geolocation is None:
            text += "Public IP: "
            text += Text("Checking...", style="blink")
        else:
            text += f"Public IP: {local_ip_geolocation}"

        if supervisor_state.is_fetching_geolocation:
            text += ""

        return text

    def get_targets_info(self) -> Text:
        supervisor_state = self.supervisor_state
        if supervisor_state is None:
            return Text()

        text = Text()

        n_targets = supervisor_state.targets_count
        if n_targets == 1:
            text += f"1 target"
        elif n_targets > 1:
            text += f"{n_targets} targets"
        else:
            text += f"No targets"

        if supervisor_state.is_fetching_targets:
            text += Text(" (fetching)", style="blink")

        return text

    def get_proxies_info(self) -> Text:
        supervisor_state = self.supervisor_state
        if supervisor_state is None:
            return Text()

        text = Text()

        n_proxies = supervisor_state.proxies_count
        if n_proxies == 1:
            text += f"1 proxy"
        elif n_proxies > 1:
            text += f"{n_proxies} proxies"
        else:
            text += f"No proxies"

        if supervisor_state.is_fetching_proxies:
            text += Text(" (fetching)", style="blink")

        return text

    def get_attacks_info(self) -> Text:
        supervisor_state = self.supervisor_state
        if supervisor_state is None:
            return Text()

        text = Text()

        n_attacks = supervisor_state.attack_processes_count
        if n_attacks == 1:
            text += f"1 attack process"
        elif n_attacks > 1:
            text += f"{n_attacks} attack processes"
        else:
            text += f"No attack processes"

        return text

    # PROPERTIES

    @property
    def supervisor_state(self) -> AttackSupervisorState:
        return self.app.supervisor_state
