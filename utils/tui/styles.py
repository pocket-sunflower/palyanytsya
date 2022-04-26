from rich.style import Style


class Styles:
    ua_yellow = Style(color="yellow")
    ua_blue = Style(color="blue")
    green = Style(color="green", italic=True)
    red = Style(color="red")
    red_blink = red + Style(blink=True)
    status_bar = Style(color="black", bgcolor="yellow")

    selected = Style(color="black", bgcolor="white")
    muted = Style(color="rgb(128,128,128)")

    waiting = Style(blink=True)

    ok = Style(color="green")
    warning = Style(color="yellow")
    bad = Style(color="red")
    critical = Style(color="red", bold=True)

    special = Style(color="cyan")

    attacks_header = Style(color="black", bgcolor="dark_orange")

