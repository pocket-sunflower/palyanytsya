"""
Implementations of utilities for checking target's health on layers 4 and 7.
"""
from __future__ import annotations

import enum
import itertools
import threading
import time
from _socket import IPPROTO_TCP, SHUT_RDWR
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from queue import Queue
from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from time import perf_counter, sleep
from typing import List

from PyRoxy import Proxy
from icmplib import Host
from requests import Response, RequestException, get
from yarl import URL

from MHDDoS.methods.layer_7 import Layer7
from MHDDoS.utils.targets import Target
from utils.misc import TimeInterval


class Connectivity(enum.IntEnum):
    UNKNOWN = -2
    UNREACHABLE = -1
    UNRESPONSIVE = 0
    PARTIALLY_REACHABLE = 1
    REACHABLE = 2

    def __bool__(self):
        return self.value > 0

    @staticmethod
    def get_for_layer_4(layer_4: Host | None) -> Connectivity:
        if layer_4 is None:
            return Connectivity.UNKNOWN
        elif layer_4.is_alive:
            successful_pings_ratio = float(layer_4.packets_sent) / layer_4.packets_received
            if successful_pings_ratio >= 0.9:
                return Connectivity.REACHABLE
            elif 0 < successful_pings_ratio < 0.9:
                return Connectivity.PARTIALLY_REACHABLE
            else:
                return Connectivity.UNREACHABLE
        else:
            return Connectivity.UNREACHABLE

    @staticmethod
    def get_for_layer_4_proxied(layer_4_proxied: List[Host | None] | None) -> Connectivity:
        if not layer_4_proxied:
            return Connectivity.UNKNOWN

        all_connectivities = [Connectivity.get_for_layer_4(r) for r in layer_4_proxied]
        best_connectivity = max(all_connectivities)
        return best_connectivity

    @staticmethod
    def get_for_layer_7(layer_7: Response | RequestException | None) -> Connectivity:
        if isinstance(layer_7, Response):
            response: Response = layer_7
            if response.status_code == 200:
                return Connectivity.REACHABLE
            elif response.status_code >= 500:
                return Connectivity.UNRESPONSIVE
            else:
                return Connectivity.PARTIALLY_REACHABLE

        elif isinstance(layer_7, RequestException):
            exception: RequestException = layer_7
            return Connectivity.UNREACHABLE

        else:
            return Connectivity.UNKNOWN

    @staticmethod
    def get_for_layer_7_proxied(layer_7_proxied: List[Response | RequestException | None] | None) -> Connectivity:
        if not layer_7_proxied:
            return Connectivity.UNKNOWN

        all_connectivities = [Connectivity.get_for_layer_7(r) for r in layer_7_proxied]
        best_connectivity = max(all_connectivities)
        return best_connectivity


@dataclass(slots=True, order=True, frozen=True)
class ConnectivityState:
    timestamp: float
    target: Target

    layer_7: Response | RequestException | None
    layer_4: Host | None
    layer_7_proxied: List[Response | RequestException]
    layer_4_proxied: List[Host]

    def __post_init__(self):
        connectivity_l4: Connectivity = max(
            Connectivity.get_for_layer_4(self.layer_4),
            Connectivity.get_for_layer_4_proxied(self.layer_4_proxied)
        )
        object.__setattr__(self, 'connectivity_l4', connectivity_l4)

        connectivity_l7: Connectivity = max(
            Connectivity.get_for_layer_7(self.layer_7),
            Connectivity.get_for_layer_7_proxied(self.layer_7_proxied)
        )
        object.__setattr__(self, 'connectivity_l7', connectivity_l7)

        validated_proxies_indices: List[int] = []

        if self.target.is_layer_4 and self.layer_4_proxied:
            for i, result in enumerate(self.layer_4_proxied):
                if Connectivity.get_for_layer_4(result):
                    validated_proxies_indices.append(i)

        if self.target.is_layer_7 and self.layer_7_proxied:
            for i, result in enumerate(self.layer_7_proxied):
                if Connectivity.get_for_layer_7(result):
                    validated_proxies_indices.append(i)

        object.__setattr__(self, 'validated_proxies_indices', validated_proxies_indices)

    @property
    def uses_proxies(self) -> bool:
        return bool(self.layer_4_proxied) or bool(self.layer_7_proxied)

    @property
    def has_valid_proxies(self) -> bool:
        return self.valid_proxies_count > 0

    @property
    def valid_proxies_count(self) -> int: return len(self.validated_proxies_indices)

    @property
    def total_proxies_count(self) -> int:
        if self.layer_4_proxied:
            return len(self.layer_4_proxied)
        if self.layer_7_proxied:
            return len(self.layer_7_proxied)
        return 0

    def get_valid_proxies(self, original_proxies_list: List[Proxy]) -> List[Proxy]:
        """
        Returns a list of proxies which could connect to the target.
        Requires the original proxy list that was used for this connectivity check.

        Args:
            original_proxies_list: Original proxy list used for validation.

        Returns:
            List of valid proxies.
        """
        return [original_proxies_list[i] for i in self.validated_proxies_indices]


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
            except Exception as e:
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


class ConnectivityChecker(Thread):

    def __init__(self,
                 interval: float,
                 target: Target,
                 proxies: List[Proxy] | None,
                 state_queue: Queue,
                 l4_retries=1,
                 l4_timeout=2,
                 l4_interval=0.2,
                 l7_timeout=10,
                 max_concurrent_connections: int = 1000):
        """
        Constantly checks connectivity_state of the given target and feeds results in the given Queue.

        Args:
            interval: Interval between checks in seconds.
            target: Target to check.
            proxies: List of proxies to use for connectivity_state check.
            state_queue: Queue where the check results will be put to.
        """
        Thread.__init__(self, daemon=True)

        stop_event = threading.Event()
        stop_event.clear()
        self._stop_event = stop_event

        self.interval = TimeInterval(interval)
        self.target = target
        self.proxies = proxies
        self.state_queue = state_queue

        self.l4_retries = l4_retries
        self.l4_timeout = l4_timeout
        self.l4_interval = l4_interval
        self.l7_timeout = l7_timeout

        self.max_concurrent_connections = max_concurrent_connections

    def run(self) -> None:
        while not self._stop_event.is_set():

            l4_result, l4_proxied_results = ConnectivityUtils.connectivity_check_layer_4(
                ip=self.target.ip,
                port=self.target.port,
                proxies=self.proxies,
                retries=self.l4_retries,
                timeout=self.l4_timeout,
                interval=self.l4_interval,
                max_concurrent_connections=self.max_concurrent_connections
            ) if self.target.is_layer_4 else (None, None)

            l7_response, l7_proxied_responses = ConnectivityUtils.connectivity_check_layer_7(
                address=self.target.url,
                proxies=self.proxies,
                timeout=self.l7_timeout,
                max_concurrent_connections=self.max_concurrent_connections
            ) if self.target.is_layer_7 else (None, None)

            state = ConnectivityState(
                timestamp=time.time(),
                target=self.target,
                layer_7=l7_response,
                layer_4=l4_result,
                layer_7_proxied=l7_proxied_responses,
                layer_4_proxied=l4_proxied_results,
            )
            self.state_queue.put(state)

            while (not self.interval.check_if_has_passed()) and (not self._stop_event.is_set()):
                time.sleep(0.01)

    def stop(self):
        self._stop_event.set()
