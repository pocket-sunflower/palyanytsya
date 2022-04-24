from textual import events
from textual.app import App
from textual.widgets import Placeholder

from utils.tui.flair import Flair


class PalyanytsyaApp(App):
    """The Palyanytsya Application"""

    async def on_load(self, event: events.Load) -> None:
        """Bind keys with the app loads (but before entering application mode)"""
        await self.bind("b", "view.toggle('sidebar')", "Toggle sidebar")
        await self.bind("q", "quit", "Quit")
        await self.bind("escape", "quit", "Quit")

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

        await self.view.dock(Flair(), edge="top", size=12)
        await self.view.dock(*top_group, edge="top", size=10)
        await self.view.dock(*bottom_group, edge="bottom", size=2)


def run_tui():
    PalyanytsyaApp.run(title="Palyanytsya TUI", log="logs/palyanytsya.log")
