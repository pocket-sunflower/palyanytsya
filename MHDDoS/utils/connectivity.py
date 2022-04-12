"""
Implementations of utilities for checking target's health on layers 4 and 7.
"""

import itertools
import time
from _socket import IPPROTO_TCP, SHUT_RDWR
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from queue import Queue
from socket import socket, AF_INET, SOCK_STREAM
from time import perf_counter, sleep
from typing import Union, List

from PyRoxy import Proxy
from icmplib import Host
from requests import Response, RequestException, get
from yarl import URL

from MHDDoS.methods.layer_7 import Layer7
from MHDDoS.methods.methods import Methods
from MHDDoS.utils.targets import Target


class ConnectivityUtils:
    @staticmethod
    def layer_4_ping(ip: str, port: int, retries: int = 5, timeout: float = 2, interval: float = 0.2, proxy: Proxy = None) -> Host:
        round_trip_times = []
        # print(f"// proxy {proxy.host}:{proxy.port} /")
        for _ in range(retries):
            try:
                with (socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) if proxy is None else proxy.open_socket()) as s:
                    start_time = perf_counter()
                    # print(f"proxy {proxy.host}:{proxy.port} - trying...")
                    s.settimeout(timeout)
                    s.connect((ip, port))
                    s.shutdown(SHUT_RDWR)
                    duration = perf_counter() - start_time
                    round_trip_times.append(duration * 1000)
                    sleep(interval)
                    # print(f"proxy {proxy.host}:{proxy.port} - rtt {duration}")
            except OSError as e:  # https://docs.python.org/3/library/socket.html#exceptions
                # print(f"proxy {proxy.host}:{proxy.port} - {e}")
                pass

        return Host(ip, retries, round_trip_times)

    @staticmethod
    def layer_7_ping(address: URL, timeout: float = 10, proxy: Proxy = None) -> Response | RequestException:
        # craft fake headers to make it look like a browser request
        mhddos_layer_7 = Layer7(address, address.host)
        fake_headers_string = mhddos_layer_7.randHeadercontent
        fake_headers_dict = {}
        for entry in fake_headers_string.strip("\n").split("\n"):
            header_name = entry.split(": ")[0]
            header_value = entry.replace(f"{header_name}: ", "").strip("\r")
            fake_headers_dict[header_name] = header_value

        # send a GET request
        try:
            proxies = None
            if proxy:
                proxies = {
                    "http": proxy.__str__(),
                    "https": proxy.__str__()
                }

            return get(address.human_repr(),
                       timeout=timeout,
                       proxies=proxies,
                       headers=fake_headers_dict)

        except RequestException as exception:
            return exception  # indeterminate

    @staticmethod
    def connectivity_check_layer_4(ip: str,
                                   port: int,
                                   retries: int = 5,
                                   timeout: float = 2,
                                   interval: float = 0.2,
                                   proxies: List[Proxy] = None,
                                   max_concurrent_connections: int = 1000) -> (Host, List[Host]):
        """
        Checks connectivity_state to the target on Layer 4 (depending on the selected protocol and attack method).

        Args:
            ip: IP of the target.
            port: Port of the target
            retries: Number of retries when checking connectivity_state.
            timeout: Timeout when checking connectivity_state.
            interval: Interval between retries.
            proxies: List of the proxies to use where possible for connectivity_state check.
            max_concurrent_connections: Maximum number of concurrent connections to the target. Has effect only when using proxies.
                Limiting this number may help to prevent overflowing the target with connections and make check more reliable.

        Returns:
            A tuple containing
              (1) Host status for Layer 4.
              (2) Proxied host statuses for Layer 4 in a list corresponding to the provided list of proxies.
        """
        layer_4_result = None
        layer_4_proxied_results = None
        if proxies is not None and len(proxies) > 0:
            # these Layer 4 methods can use proxies, so check for every proxy using proxied TCP socket
            with ThreadPoolExecutor(max_concurrent_connections, "layer_4_ping_") as executor:
                # we use executor.map to ensure that the order of the ping results corresponds to the passed list of proxies
                n = len(proxies)
                layer_4_proxied_results = list(executor.map(ConnectivityUtils.layer_4_ping,
                                                            itertools.repeat(ip, n),
                                                            itertools.repeat(port, n),
                                                            itertools.repeat(retries, n),
                                                            itertools.repeat(timeout, n),
                                                            itertools.repeat(interval, n),
                                                            proxies))
        else:
            # check using TCP socket without proxy
            layer_4_result = ConnectivityUtils.layer_4_ping(ip, port, retries=retries, timeout=timeout, interval=interval)

        return layer_4_result, layer_4_proxied_results

    @staticmethod
    def connectivity_check_layer_7(address: URL,
                                   timeout: float = 10,
                                   proxies: List[Proxy] = None,
                                   max_concurrent_connections: int = 1000) -> (Response | RequestException | None, List[Response | RequestException] | None):
        """

        Args:
            address: IP or URL of the target.
            timeout: Timeout when checking connectivity_state.
            proxies: List of the proxies to use where possible for connectivity_state check.
            max_concurrent_connections: Maximum number of concurrent connections to the target. Has effect only when using proxies.
                Limiting this number may help to prevent overflowing the target with connections and make check more reliable.

        Returns:
            A tuple containing
              (1) HTTP response for Layer 7 (or RequestException if it occurs).
              (2) Proxied HTTP responses for Layer 7 (or RequestExceptions if they occur) in a list corresponding to the provided list of proxies.
        """
        # handle Layer 7
        layer_7_response = None
        layer_7_proxied_responses = None
        if proxies is not None and len(proxies) > 0:
            # proxies are provided, so check for every proxy
            with ThreadPoolExecutor(max_concurrent_connections, "layer_7_ping_") as executor:
                # we use executor.map to ensure that the order of the responses corresponds to the passed list of proxies
                n = len(proxies)
                layer_7_proxied_responses = list(executor.map(ConnectivityUtils.layer_7_ping,
                                                              itertools.repeat(address, n),
                                                              itertools.repeat(timeout, n),
                                                              proxies))
        else:
            layer_7_response = ConnectivityUtils.layer_7_ping(address, timeout)

        return layer_7_response, layer_7_proxied_responses


@dataclass
class ConnectivityState:
    layer_7: Response | RequestException | None
    layer_4: Host | None
    layer_7_proxied: List[Response | RequestException]
    layer_4_proxied: List[Host]
    timestamp: float


def connectivity_check_loop(interval: float,
                            target: Target,
                            method: str,
                            proxies: Union[set, None],
                            state_queue: Queue):
    """
    Constantly checks connectivity_state of the given target and feeds results in the given Queue.

    Args:
        interval: Interval between checks in seconds.
        target: Target to check.
        method: Attack method used for
        proxies: List of proxies to use for connectivity_state check.
        state_queue: Queue where the check results will be put to.
    """
    while True:
        l4_result, l4_proxied_results = ConnectivityUtils.connectivity_check_layer_4(
            ip=target.ip,
            port=target.port,
            proxies=proxies if method in Methods.WHICH_SUPPORT_PROXIES else None,
            retries=1,
            timeout=2,
            interval=0.2
        )
        l7_response, l7_proxied_responses = ConnectivityUtils.connectivity_check_layer_7(
            address=target.url,
            proxies=proxies,
            timeout=10
        )
        state = ConnectivityState(
            layer_7=l7_response,
            layer_4=l4_result,
            layer_7_proxied=l7_proxied_responses,
            layer_4_proxied=l4_proxied_results,
            timestamp=time.time()
        )
        state_queue.put(state)

        sleep(interval)
