from time import time
from typing import List

from humanfriendly.terminal import ansi_wrap
from icmplib import Host
from requests import Response, RequestException


class CyclicPeriods:

    def __init__(self, update_interval: float = 0.5, max_periods: int = 3):
        self.update_interval = update_interval
        self.max_periods = max_periods

    def __str__(self):
        n_periods = self.max_periods - int((time() * 1.0 / self.update_interval % self.max_periods))
        periods = "".join(["." for _ in range(n_periods)])
        return periods


def craft_outreach_log_message(is_first_health_check_done: bool,
                               last_target_health_check_timestamp: float,
                               last_l4_result: Host,
                               last_l4_proxied_results: List[Host],
                               last_l7_response: Response,
                               last_l7_proxied_responses: List[Response]):
    status_string = ""

    # craft time string
    time_since_last_update = time() - last_target_health_check_timestamp
    time_string = f"updated {int(time_since_last_update):.0f} {'second' if int(time_since_last_update) == 1 else 'seconds'} ago"

    # craft outreach summary header
    if last_target_health_check_timestamp > 0:
        status_string += f"    Outreach ({time_string}):\n"
    else:
        status_string += f"    Outreach:\n"

    # craft Layer 4 check summary line
    status_string += "       Summary:\n"
    status_string += "          Layer 4: "
    if is_first_health_check_done:
        status_string += craft_layer_4_outreach_summary_string(last_l4_result, last_l4_proxied_results)
    else:
        status_string += f"Checking if the target is reachable{CyclicPeriods()}"

    status_string += "\n"

    # craft Layer 7 check summary line
    status_string += "          Layer 7: "
    if is_first_health_check_done:
        status_string += craft_layer_7_outreach_summary_string(last_l7_response, last_l7_proxied_responses)
    else:
        status_string += f"Checking target health{CyclicPeriods()}"

    status_string += "\n"

    if is_first_health_check_done:
        # craft detailed stats
        status_string += f"       Details:\n"
        is_using_proxies = (last_l4_proxied_results is not None) and len(last_l4_proxied_results) > 0
        if is_using_proxies:
            for i in range(len(last_l4_proxied_results)):
                status_string += f"          "
                status_string += f"Through proxy {(i+1):<2} - "
                l4 = last_l4_proxied_results[i]
                l7 = last_l7_proxied_responses[i]
                status_string += craft_detailed_outreach_stats_string(l4, l7)
                status_string += "\n"
        else:
            status_string += f"          "
            status_string += f"Direct to target - "
            status_string += craft_detailed_outreach_stats_string(last_l4_result, last_l7_response)
            status_string += "\n"

    return status_string


def craft_layer_4_outreach_summary_string(l4_result: Host, l4_proxied_results: List[Host]) -> str:
    message = "Target is "

    if l4_result is not None:
        r = l4_result
        if r.is_alive:
            successful_pings_ratio = float(r.packets_sent) / r.packets_received
            if successful_pings_ratio > 0.5:
                message += ansi_wrap(f"REACHABLE", color="green")
                message += f" from our IP (ping {r.avg_rtt:.0f} ms, no packets lost)."
            else:
                message += ansi_wrap(f"PARTIALLY REACHABLE", color="yellow")
                message += f" from our IP (ping {r.avg_rtt:.0f} ms, {r.packet_loss * 100:.0f}% packet loss)."
        else:
            message += ansi_wrap(f"UNREACHABLE", color="red")
            message += f" from our IP ({r.packet_loss * 100:.0f}% packet loss)."
            message += ansi_wrap(f" It may be down. We are shooting blanks right now.", color="red")
    elif l4_proxied_results is not None and len(l4_proxied_results) > 0:
        # collect stats about the results
        results = l4_proxied_results.copy()
        successful_pings = [r for r in results if r.is_alive]
        n_successful_pings = len(successful_pings)
        n_proxies = len(results)
        best_avg_ping = min([r.avg_rtt for r in results if r.is_alive])
        # craft average ping result for all proxies
        all_rtts = []
        _ = [all_rtts.extend(r.rtts) for r in results]

        r = Host(
            address=results[0].address,
            packets_sent=sum([r.packets_sent for r in results]),
            rtts=all_rtts
        )

        if r.is_alive:
            successful_pings_ratio = float(r.packets_received) / r.packets_sent
            if successful_pings_ratio >= 1:
                message += ansi_wrap(f"REACHABLE", color="green")
                message += f" through "
                message += ansi_wrap(f"all {n_proxies}", color="green")
                message += f" proxies (best average ping {best_avg_ping:.0f} ms, zero packet loss)."
            else:
                message += ansi_wrap(f"PARTIALLY REACHABLE", color="yellow")
                message += f" through "
                message += ansi_wrap(f"{n_successful_pings}/{n_proxies}", color="yellow")
                message += f" proxies (best ping {best_avg_ping:.0f} ms, {r.packet_loss * 100:.0f}% packet loss)."
                message += " Keep pushing."
        else:
            message += ansi_wrap(f"UNREACHABLE", color="red")
            message += f" through proxies ({r.packet_loss * 100:.0f}% packet loss)."
            message += ansi_wrap(f" Target may be down.", color="red")
    else:
        message += f"Checking if the target is reachable{CyclicPeriods()}"

    return message


def craft_layer_7_outreach_summary_string(l7_response: Response | RequestException,
                                          l7_proxied_responses: List[Response | RequestException]) -> str:
    message = "Target "

    # some helper functions
    def is_healthy(response: Response | RequestException) -> bool:
        if isinstance(response, Response):
            return response.status_code < 500
        return False

    def is_down(response: Response | RequestException) -> bool:
        if isinstance(response, Response):
            return response.status_code >= 500
        return False

    def is_indeterminate(response: Response | RequestException) -> bool:
        return response is RequestException

    if isinstance(l7_response, Response):
        if is_healthy(l7_response):
            message += "is "
            message += ansi_wrap(f"HEALTHY", color="green")
            message += f" (response code {l7_response.status_code} = {l7_response.reason})."
        elif is_down(l7_response):
            message += "may be "
            message += ansi_wrap(f"DOWN", color="red")
            message += f" (response code {l7_response.status_code} = {l7_response.reason})."
        else:
            message += "state cannot be determined."
    elif isinstance(l7_response, RequestException):
        exception: RequestException = l7_response
        message += "may be "
        message += ansi_wrap(f"DOWN", color="red")
        message += f" ({type(exception).__name__} when making a request)."
    elif l7_proxied_responses is not None and len(l7_proxied_responses) > 0:
        n_proxies = len(l7_proxied_responses)
        n_healthy = len([r for r in l7_proxied_responses if is_healthy(r)])
        n_down = len([r for r in l7_proxied_responses if is_down(r)])
        n_indeterminate = len([r for r in l7_proxied_responses if is_indeterminate(r)])

        if n_healthy > 0 and n_down == 0 and n_indeterminate == 0:
            message += "is "
            message += ansi_wrap(f"HEALTHY", color="green")
            if n_proxies > 1:
                message += f" (got healthy responses through all {n_proxies} proxies)."
            else:
                message += f" (got healthy response through the proxy)."
        elif n_healthy > 0 and (n_down > 0 or n_indeterminate > 0):
            message += "is "
            message += ansi_wrap(f"STRUGGLING", color="yellow")
            message += f" (got healthy responses only through {n_healthy}/{n_proxies} proxies)."
        elif n_healthy == 0 and n_down > 0:
            message += "may be "
            message += ansi_wrap(f"DOWN", color="red")
            if n_proxies > 1:
                message += f" (got bad or no responses through all of the {n_proxies} proxies)."
            else:
                if n_down == 1:
                    message += f" (got bad response through the proxy)."
                else:
                    message += f" (got no response through the proxy)."
        else:
            if n_proxies > 1:
                message += "is in limbo. State could not be determined through any of the proxies."
            else:
                message += "is in limbo. State could not be determined through the proxy."
    else:
        message += "did not respond. It may be "
        message += ansi_wrap("down", color="red")
        message += f", or it does not support HTTP protocol."

    return message


def craft_detailed_outreach_stats_string(l4: Host,
                                         l7: Response | RequestException):
    message = ""

    # is alive
    if l4.is_alive:
        s = ansi_wrap("●", color="green")
    else:
        s = ansi_wrap("●", color="red")
    message += f"{s:>1} "

    # average ping
    padding = 7
    if l4.is_alive:
        s = ansi_wrap(f"{l4.avg_rtt:.0f} ms".ljust(padding), color="green")
    else:
        s = ansi_wrap(f"{CyclicPeriods()}".ljust(padding), color="red")
    message += f"{s} - "

    # response / exception
    padding = 0
    if isinstance(l7, Response):
        if l7.status_code < 400:
            color = "green"
        elif l7.status_code < 500:
            color = "yellow"
        else:
            color = "red"
        s = ansi_wrap(f"{l7.status_code} {l7.reason}".ljust(padding), color=color)
    elif isinstance(l7, RequestException):
        s = f"{type(l7).__name__}"
        s = ansi_wrap(s.ljust(padding), color="red")
    else:
        s = ansi_wrap(f"{CyclicPeriods()}".ljust(padding), color="red")
    message += f"{s}"

    return message
