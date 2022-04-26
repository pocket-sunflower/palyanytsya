import math

from rich.style import Style
from rich.table import Table
from rich.text import Text

from MHDDoS.attack import AttackState
from MHDDoS.methods.tools import Tools
from MHDDoS.utils.connectivity import Connectivity, ConnectivityState
from MHDDoS.utils.targets import Target
from utils.tui.styles import Styles


class SharedMenuUtils:

    @staticmethod
    def add_header_to_attack_state_table(table: Table) -> None:
        table.add_column("Target", justify="center", max_width=40)
        table.add_column("Proxies", justify="center")
        table.add_column("Connectivity", justify="center")
        table.add_column("Methods", justify="center")
        table.add_column("Requests/s (total)", justify="center")
        table.add_column("Bytes/s (total)", justify="center")
        table.add_column("Threads", justify="center")

        table.header_style = Styles.attacks_header

    @staticmethod
    def add_attack_row_to_attack_state_table(table: Table, attack: AttackState) -> None:
        # target status
        if attack.has_connectivity_data:
            target_status_string = SharedMenuUtils.get_concise_target_connectivity_text(attack.target, attack.connectivity_state)
        else:
            target_status_string = Text("Checking...", style=Styles.muted + Styles.waiting)

        # methods
        if attack.attack_methods is None:
            attack_methods_string = Text("Validating...", style=Styles.muted)
        elif len(attack.attack_methods) == 0:
            attack_methods_string = Text("0 (no valid \n"
                                         "methods found)", style=Styles.bad)
        else:
            n_attack_methods = len(attack.attack_methods)
            first_two = attack.attack_methods[0:2] if (n_attack_methods > 1) else attack.attack_methods
            if n_attack_methods > 2:
                first = attack.attack_methods[0]
                attack_methods_string = Text(f"{first}\n(+{n_attack_methods - 1} more)")
            else:
                attack_methods_string = Text("\n".join(first_two))

            attack_methods_string.style = Styles.special

        # requests
        rps = Text(f"{Tools.humanformat(attack.requests_per_second)} r/s")
        if attack.requests_per_second == 0:
            rps.style = Styles.bad
            # TODO: display change arrow
        requests_string = rps + Text(f"\n"
                                     f"({Tools.humanformat(attack.total_requests_sent)})")

        # bytes
        bps = Text(f"{Tools.humanbytes(attack.bytes_per_second)}/s")
        if attack.bytes_per_second == 0:
            bps.style = Styles.bad
            # TODO: display change arrow
        bytes_string = bps + Text(f"\n"
                                  f"({Tools.humanbytes(attack.total_bytes_sent)})")

        # proxies
        proxies_string = Text()
        n_proxies_total = attack.total_proxies_count

        if n_proxies_total == 0:
            proxies_string = Text("Not used", style=Styles.muted)
        else:
            n_validated_proxies = attack.connectivity_state.valid_proxies_count if attack.connectivity_state else 0
            n_proxies_used = attack.used_proxies_count
            n_proxies_total = attack.total_proxies_count
            n_proxies_ignored = n_proxies_total - n_proxies_used

            if n_proxies_used > 0:
                if attack.connectivity_state and attack.connectivity_state.has_valid_proxies:
                    proxies_string.append(Text(f"{n_proxies_used} used\n", style=Styles.ok))
                else:
                    proxies_string.append(Text(f"{n_proxies_used} used\n"))
            else:
                proxies_string.append(Text(f"None used\n", style=Styles.bad))

            # if n_proxies_ignored:
            #     proxies_string += f"{term.webgray(f'{n_proxies_ignored} ignored')}"

            proxies_string += Text(f"from {n_proxies_total}", style=Styles.muted)

            # if attack.proxy_validation_state.is_validating:
            #     progress = attack.proxy_validation_state.progress
            #     proxies_string += f"{term.lightcyan(f'Validating {progress * 100:.0f}%')}"  # TODO: use progress bar instead
            # else:

        row_entries = [
            str(attack.target),
            proxies_string,
            target_status_string,
            attack_methods_string,
            requests_string,
            bytes_string,
            str(attack.active_threads_count),
        ]

        table.add_row(*row_entries, end_section=True)

    @staticmethod
    def get_concise_target_connectivity_text(target: Target, connectivity_state: ConnectivityState) -> Text:
        c = Connectivity.UNKNOWN

        if target.is_layer_4:
            c = connectivity_state.connectivity_l4
        elif target.is_layer_7:
            c = connectivity_state.connectivity_l7

        style = SharedMenuUtils.get_style_for_connectivity(c)

        text = Text()

        if c == Connectivity.UNREACHABLE:
            text.append(f"Unreachable\n(may be down)")
        elif c == Connectivity.UNRESPONSIVE:
            text.append("Unresponsive\n(may be down)")
        elif c == Connectivity.PARTIALLY_REACHABLE:
            text.append("Partially\nreachable")
        elif c == Connectivity.REACHABLE:
            text.append(f"Reachable")
            if connectivity_state.uses_proxies:
                if connectivity_state.valid_proxies_count > 1:
                    text.append(f"\n(through {connectivity_state.valid_proxies_count} proxies)")
                else:
                    text.append(f"\n(through {connectivity_state.valid_proxies_count} proxies)")
        else:
            text.append("Unknown")

        text.style = style

        return text

    @staticmethod
    def get_style_for_connectivity(c: Connectivity) -> Style:
        if c == Connectivity.UNKNOWN:
            return Styles.muted
        elif c == Connectivity.UNREACHABLE:
            return Styles.critical
        elif c == Connectivity.UNRESPONSIVE:
            return Styles.bad
        elif c == Connectivity.PARTIALLY_REACHABLE:
            return Styles.warning
        elif c == Connectivity.REACHABLE:
            return Styles.ok

        return Style(color="white")@staticmethod

    @staticmethod
    def get_pagination_text(page_index: int, items_per_page: int, total_items: int) -> Text:
        page_number = page_index + 1
        total_pages = Pagination.get_total_pages(items_per_page, total_items)

        text = Text(f"PAGE {page_number}/{total_pages}")

        if total_pages == 1:
            text = Text()
        elif page_number == 1:
            text = text + Text(" ▼")
        elif page_number == total_pages:
            text = Text("▲ ") + text
        else:
            text = Text("▲ ") + text + Text(" ▼")

        return text


class Pagination:
    """
    Collection of helper functions to help with paginating tables.
    """

    @staticmethod
    def get_total_pages(items_per_page: int, total_items: int):
        total_pages = math.ceil(total_items / items_per_page)
        return total_pages

    @staticmethod
    def get_page_index(item_index: int, items_per_page: int, total_items: int) -> int:
        total_pages = math.ceil(total_items / items_per_page)
        page_index = math.floor(item_index / items_per_page)

        last_page_index = total_pages - 1
        if page_index > last_page_index:
            return last_page_index

        return page_index

    @staticmethod
    def get_page_bounds(page_index: int, items_per_page: int, total_items: int) -> (int, int):
        total_pages = math.ceil(total_items / items_per_page)
        last_page_index = total_pages - 1
        if page_index > last_page_index:
            page_index = last_page_index

        page_start_index = page_index * items_per_page

        if page_index == last_page_index:
            page_end_index = total_items
        else:
            page_end_index = page_start_index + items_per_page

        return page_start_index, page_end_index

    @staticmethod
    def get_item_index_on_page(item_index: int, items_per_page: int) -> int:
        item_index_on_page = item_index % items_per_page
        return item_index_on_page
