from rich.style import Style


class Colors:
    yellow = "#FFD700"
    blue = "#0057B8"
    green = "#00FF00"
    red = "#FF0000"
    gray = "#696969"
    black = "#000000"
    white = "#FFFFFF"
    orange_warning = "#FFA500"
    dark_orange = "#FF8C00"
    dodger_blue = "#1E90FF"
    gold = "#FFD700"
    turquoise = "#40E0D0"


class Styles:
    ua_yellow = Style(color=Colors.yellow)
    ua_blue = Style(color=Colors.blue)
    green = Style(color=Colors.green, italic=True)
    red = Style(color=Colors.red)
    red_blink = red + Style(blink=True)
    status_bar = Style(color=Colors.black, bgcolor=Colors.yellow)

    selected = Style(color=Colors.black, bgcolor=Colors.white)
    muted = Style(color=Colors.gray)

    waiting = Style(blink=True)

    ok = Style(color=Colors.green)
    warning = Style(color=Colors.orange_warning)
    bad = Style(color=Colors.red)
    critical = Style(color=Colors.red, bold=True)

    special = Style(color=Colors.turquoise)

    attacks_header = Style(color=Colors.black, bgcolor=Colors.dark_orange)
    connectivity_header = Style(color=Colors.black, bgcolor=Colors.dodger_blue)
    navigation_key = Style(color=Colors.black, bgcolor=Colors.gold, italic=True)
    navigation_bar = Style(color=Colors.white, bgcolor=Colors.black)
