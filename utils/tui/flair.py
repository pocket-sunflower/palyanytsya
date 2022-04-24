import math

from rich.console import RenderableType
from rich.style import Style
from rich.text import Text
from textual import events
from textual.reactive import Reactive
from textual.widget import Widget

from utils.tui.styles import Styles


class Flair(Widget):
    mouse_over = Reactive(False)
    clicked = Reactive(False)

    def render(self) -> RenderableType:

        s = "[i]clicked[/]" if self.clicked else ""
        # return Panel(f"Hello [b]World[/b] {s}", style=("on red" if self.mouse_over else ""))
        flair = self.get_flair_with_gradient()

        return flair

    def on_enter(self) -> None:
        self.mouse_over = True

    def on_leave(self) -> None:
        self.mouse_over = False

    def on_click(self, event: events.Click) -> None:
        self.clicked = True

    @staticmethod
    def get_flair_string() -> Text:

        heart = Text("♥", style=Styles.red)

        flair = Text()
        flair.append("\n")
        flair.append("A heavy-duty freedom-infused MHDDoS wrapper...\n", style=Styles.green)
        flair.append("\n")
        flair.append("██████╗░░█████╗░██╗░░░░░██╗░░░██╗░█████╗░███╗░░██╗██╗░░░██╗████████╗░██████╗██╗░░░██╗░█████╗░\n", style=Styles.ua_blue)
        flair.append("██╔══██╗██╔══██╗██║░░░░░╚██╗░██╔╝██╔══██╗████╗░██║╚██╗░██╔╝╚══██╔══╝██╔════╝╚██╗░██╔╝██╔══██╗\n", style=Styles.ua_blue)
        flair.append("██████╔╝███████║██║░░░░░░╚████╔╝░███████║██╔██╗██║░╚████╔╝░░░░██║░░░╚█████╗░░╚████╔╝░███████║\n", style=Styles.ua_blue)
        flair.append("██╔═══╝░██╔══██║██║░░░░░░░╚██╔╝░░██╔══██║██║╚████║░░╚██╔╝░░░░░██║░░░░╚═══██╗░░╚██╔╝░░██╔══██║\n", style=Styles.ua_yellow)
        flair.append("██║░░░░░██║░░██║███████╗░░░██║░░░██║░░██║██║░╚███║░░░██║░░░░░░██║░░░██████╔╝░░░██║░░░██║░░██║\n", style=Styles.ua_yellow)
        flair.append("╚═╝░░░░░╚═╝░░╚═╝╚══════╝░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚══╝░░░╚═╝░░░░░░╚═╝░░░╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝\n", style=Styles.ua_yellow)
        flair.append("\n")
        flair.append(f"                                                                  ...from Ukraine with love ", style=Styles.green)
        flair.append(heart)
        flair.append("\n")

        flair.overflow = "crop"
        flair.no_wrap = True

        return flair

    def get_flair_with_gradient(self) -> Text:
        gradient = ["█", "▓", "▒", "░", " "]

        flair_text = Flair.get_flair_string()
        flair_text_dimensions = self.console.measure(flair_text)
        flair_text_width = flair_text_dimensions.maximum

        flair_text.pad_right(flair_text_width)

        # calculate gradient dimensions
        gradient_steps_count = len(gradient)
        non_flair_text_width = self.size.width - flair_text_width
        left_side_width = int(math.floor(non_flair_text_width / 2))
        right_side_width = int(math.ceil(non_flair_text_width / 2))
        step = int(right_side_width / gradient_steps_count)
        left_side_extra_width = left_side_width - step * gradient_steps_count
        right_side_extra_width = right_side_width - step * gradient_steps_count

        def craft_flair_side(left_to_right: bool, style: Style) -> Text:
            g_list = gradient.copy()

            if not left_to_right:
                g_list.reverse()

            s = Text()

            if left_to_right:
                for k in range(left_side_extra_width):
                    s += g_list[0]

            for j in range(gradient_steps_count):
                for k in range(step):
                    s += g_list[j]

            if not left_to_right:
                for k in range(right_side_extra_width):
                    s += g_list[-1]

            s.style = style
            return s

        flair = Text()
        flair_text_split = flair_text.split("\n")
        flair_text_height = len(flair_text_split)
        flair_height = flair_text_height

        for i in range(flair_height):
            color = Styles.ua_blue if (i < flair_height // 2) else Styles.ua_yellow
            flair.append(craft_flair_side(True, color))

            line = flair_text_split[i] if (i < flair_text_height) else Text()
            line_width = len(line)
            line.pad_right(flair_text_width - line_width)
            flair.append(line)

            flair.append(craft_flair_side(False, color))
            flair.append("\n")

        flair.overflow = "crop"
        flair.no_wrap = True

        return flair
