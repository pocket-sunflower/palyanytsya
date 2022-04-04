"""
Implementations of utilities for checking target's health on layers 4 and 7.
"""

import itertools
from _socket import IPPROTO_TCP, SHUT_RDWR
from concurrent.futures import ThreadPoolExecutor
from socket import socket, AF_INET, SOCK_STREAM
from time import perf_counter, sleep
from typing import Union, List

from PyRoxy import Proxy
from icmplib import Host
from requests import Response, RequestException, get
from yarl import URL

from MHDDoS.methods.layer_7 import Layer7
from MHDDoS.methods.methods import Methods
from MHDDoS.methods.tools import Tools


class TargetHealthCheckUtils:
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
    def layer_7_ping(url: str, timeout: float = 10, proxy: Proxy = None) -> Response | RequestException:
        # craft fake headers to make it look like a browser request
        url_object = URL(url)
        mhddos_layer_7 = Layer7(url_object, url_object.host)
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

            return get(url,
                       timeout=timeout,
                       proxies=proxies,
                       headers=fake_headers_dict)

        except RequestException as exception:
            return exception  # indeterminate

    @staticmethod
    def health_check(ip: Union, port: int,
                     method: str = None,
                     url: str = None,
                     proxies: List[Proxy] = None,
                     layer_4_retries: int = 5,
                     layer_4_timeout: float = 2,
                     layer_4_interval: float = 0.2,
                     layer_7_timeout: float = 10) -> (Host, Response | None, List[Host], List[Response | None]):
        """
        Checks the health of the target on Layer 4 and Layer 7
        (depending on the selected protocol and attack method).

        Args:
            ip: IP of the target.
            port: Port of the target
            method: MHDDoS attack method.
            url: URL of the target.
            proxies: List of the proxies to use where possible for connectivity check.
            layer_4_retries: Number of retries when checking connectivity via Layer 4.
            layer_4_timeout: Timeout when checking connectivity via Layer 4.
            layer_4_interval: Interval between retries when checking connectivity via Layer 4.
            layer_7_timeout: Timeout when checking connectivity via Layer 7.

        Returns:
            A tuple containing
              (1) Host status for Layer 4.
              (2) HTTP response for Layer 7.
              (3) Proxied host statuses for Layer 4 in a list corresponding to the provided list of proxies.
              (4) Proxied HTTP responses for Layer 7 in a list corresponding to the provided list of proxies.

        Notes:
            Layer 7 results will contain RequestException if the request fails.
        """

        # print(f"Health check for {url} ({ip}:{port}) with {method}")

        # handle Layer 4
        layer_4_result = None
        layer_4_proxied_results = None
        if (method in {"MINECRAFT", "MCBOT", "TCP"} or method in Methods.LAYER7_METHODS) \
                and proxies is not None and len(proxies) > 0:
            # these Layer 4 methods can use proxies, so check for every proxy using proxied TCP socket
            with ThreadPoolExecutor() as executor:
                # we use executor.map to ensure that the order of the ping results corresponds to the passed list of proxies
                n = len(proxies)
                layer_4_proxied_results = list(executor.map(TargetHealthCheckUtils.layer_4_ping,
                                                            itertools.repeat(ip, n),
                                                            itertools.repeat(port, n),
                                                            itertools.repeat(layer_4_retries, n),
                                                            itertools.repeat(layer_4_timeout, n),
                                                            itertools.repeat(layer_4_interval, n),
                                                            proxies))
        else:
            # check using TCP socket without proxy
            layer_4_result = TargetHealthCheckUtils.layer_4_ping(ip, port, retries=layer_4_retries, timeout=layer_4_timeout, interval=layer_4_interval)

        # handle Layer 7
        layer_7_response = None
        layer_7_proxied_responses = None
        url = Tools.ensure_http_present(url if url is not None else ip)
        if proxies is not None and len(proxies) > 0:
            # proxies are provided, so check for every proxy
            with ThreadPoolExecutor() as executor:
                # we use executor.map to ensure that the order of the responses corresponds to the passed list of proxies
                n = len(proxies)
                layer_7_proxied_responses = list(executor.map(TargetHealthCheckUtils.layer_7_ping,
                                                              itertools.repeat(url, n),
                                                              itertools.repeat(layer_7_timeout, n),
                                                              proxies))
        else:
            layer_7_response = TargetHealthCheckUtils.layer_7_ping(url, layer_7_timeout)

        return layer_4_result, layer_7_response, layer_4_proxied_results, layer_7_proxied_responses
