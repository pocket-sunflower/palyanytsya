import time


def clear_lines_from_console(n_lines: int):
    GO_TO_PREVIOUS_LINE = f"\033[A"
    GO_TO_LINE_START = "\r"
    CLEAR_LINE = "\033[2K"

    if n_lines <= 0:
        return

    returner = f"{GO_TO_LINE_START}{CLEAR_LINE}"
    for _ in range(n_lines):
        returner += f"{GO_TO_PREVIOUS_LINE}{GO_TO_LINE_START}{CLEAR_LINE}"

    print(returner, end="", flush=True)
