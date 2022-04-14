import logging
import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass
from multiprocessing import Queue
from pathlib import Path
from random import choice
from threading import Thread
from time import perf_counter, sleep
from typing import Set, List

from PyRoxy import Proxy, ProxyType, ProxyUtiles
from humanfriendly.terminal import ansi_wrap
from requests import ReadTimeout, get

from MHDDoS.utils.config_files import read_configuration_file_lines
from MHDDoS.utils.connectivity import ConnectivityUtils
from MHDDoS.utils.misc import Counter
from MHDDoS.utils.targets import Target
from MHDDoS.utils.text import CyclicPeriods
from utils.misc import TimeInterval

logger = logging.getLogger()


def load_proxies(file_path_or_url: str) -> List[Proxy] | None:
    """
    Loads the list of proxies from the given file, and makes sure they are unique.

    Args:
        file_path_or_url: Path to or URL of the text file with the list of proxy server addresses (one per line).

    Returns:
        The list of loaded proxies. None if no proxies were loaded.
    """
    # read proxies from file
    proxies_lines = read_configuration_file_lines(file_path_or_url)
    proxies = list(ProxyUtiles.parseAll(proxies_lines))
    logger.info(f"Loaded {len(proxies)} unique proxies from '{file_path_or_url}'.")

    return proxies


@dataclass
class ProxiesValidationState:
    validation_start_timestamp: float
    expected_duration: float
    progress: float
    total_proxies: int

    # we store indices, not Proxy objects here to save performance when passing this object through Queues;
    # valid Proxies can be received using get_validated_proxies() and the original proxy list used for validation
    validated_proxies_indices: List[int]

    @property
    def is_validating(self):
        return 0 <= self.progress < 1

    @property
    def is_validation_complete(self):
        return self.progress >= 1

    @property
    def validated_proxies_count(self):
        return len(self.validated_proxies_indices)

    def get_validated_proxies(self, original_proxies_list: List[Proxy]) -> List[Proxy]:
        """
        Returns a list of validated proxies from the given original proxy list.

        Args:
            original_proxies_list: Original proxy list used for validation.

        Returns:
            List of valid proxies.
        """
        return [original_proxies_list[i] for i in self.validated_proxies_indices]


def validate_proxies(proxies: List[Proxy],
                     target: Target,
                     retries: int = 4,
                     ping_retries: int = 1,
                     ping_timeout: float = 3,
                     ping_interval: float = 0.2,
                     status_queue: Queue = None,
                     max_concurrent_connections: int = 1000,
                     stop_event: threading.Event = None) -> List[Proxy]:
    """
    Checks which of the given proxies can be used to reach the given target's IP.
    This helps to filter out proxies which are non-functional or are blocked by the target and, as a result, make the attack more effective.

    Args:
        proxies: List of proxies to check.
        target: Target to check.
        retries: How many times to run the validation before giving out the results (more retries may result in more valid proxies).
        ping_retries:
        ping_timeout:
        ping_interval:
        status_queue: Optional Queue which will receive ProxiesValidationState as the check progresses.
        max_concurrent_connections: Maximum number of concurrent connections to the target during validation.
            Limiting this number may help to prevent overflowing the target with connections and give more reliable validation results.

    Returns:
        List of proxies through which the given target's IP can be reached.
    """
    if not proxies:
        return []

    n_proxies = len(proxies)
    # TODO: factor in thread limit in L4 ping into calculation
    expected_duration = math.ceil(float(retries * (ping_retries * (ping_timeout + ping_interval))))
    validation_start_time = time.time()
    n_validated = Counter(0)
    n_tries = Counter(0)
    validated_proxies_indices: Set[int] = set()

    state: ProxiesValidationState | None = None

    def post_update():
        if status_queue is None:
            return

        nonlocal state
        state = ProxiesValidationState(
            validation_start_timestamp=validation_start_time,
            expected_duration=expected_duration,
            progress=int(n_tries) / float(retries),
            total_proxies=n_proxies,
            validated_proxies_indices=list(validated_proxies_indices),
        )
        status_queue.put(state)

    # validate given number of times
    for i in range(retries):
        if stop_event and stop_event.is_set():
            break

        post_update()

        n_tries.set(i + 1)

        _, l4_proxied_results = ConnectivityUtils.connectivity_check_layer_4(
            ip=target.ip,
            port=target.port,
            proxies=proxies,
            retries=ping_retries,
            timeout=ping_timeout,
            interval=ping_interval,
            max_concurrent_connections=max_concurrent_connections
        )

        # grab valid proxies from the results
        for j, proxy in enumerate(proxies):
            proxied_result = l4_proxied_results[j]
            if proxied_result.is_alive:
                validated_proxies_indices.add(j)

        # update stats
        n_validated.set(len(validated_proxies_indices))

    # post update after the validation is complete
    post_update()

    validated_proxies: List[Proxy] = state.get_validated_proxies(proxies)
    return validated_proxies


class ProxiesValidator(Thread):

    def __init__(self,
                 proxies: List[Proxy],
                 target: Target,
                 retries: int = 4,
                 interval: float = 120,
                 ping_retries: int = 1,
                 ping_timeout: float = 3,
                 ping_interval: float = 0.2,
                 status_queue: Queue = None):
        Thread.__init__(self, daemon=True)
        self.proxies = proxies
        self.target = target
        self.retries = retries
        self.interval = TimeInterval(interval)
        self.ping_retries = ping_retries
        self.ping_timeout = ping_timeout
        self.ping_interval = ping_interval
        self.status_queue = status_queue

        stop_event = threading.Event()
        stop_event.clear()
        self._stop_event = stop_event

    def run(self):
        while not self._stop_event.is_set():
            validate_proxies(self.proxies,
                             self.target,
                             self.retries,
                             self.ping_retries,
                             self.ping_timeout,
                             self.ping_interval,
                             self.status_queue,
                             stop_event=self._stop_event)

            while (not self.interval.check_if_has_passed()) and (not self._stop_event.is_set()):
                time.sleep(0.01)

    def stop(self):
        self._stop_event.set()


class ProxyManager:
    @staticmethod
    def DownloadFromConfig(cf, Proxy_type: int) -> Set[Proxy]:
        providers = [
            provider for provider in cf["proxy-providers"]
            if provider["type"] == Proxy_type or Proxy_type == 0
        ]
        logger.info("Downloading Proxies form %d Providers" % len(providers))
        proxies: Set[Proxy] = set()

        with ThreadPoolExecutor(len(providers)) as executor:
            future_to_download = {
                executor.submit(
                    ProxyManager.download, provider,
                    ProxyType.stringToProxyType(str(provider["type"])))
                for provider in providers
            }
            from concurrent.futures import as_completed
            for future in as_completed(future_to_download):
                for pro in future.result():
                    proxies.add(pro)
        return proxies

    @staticmethod
    def get_unique_proxies_from_set(proxies: Set[Proxy]) -> Set[Proxy]:
        unique_proxies: Set[Proxy] = set()
        seen: Set[(str, int)] = set()
        for proxy in proxies:
            proxy_signature = (proxy.host, proxy.port)
            if proxy_signature not in seen:
                seen.add(proxy_signature)
                unique_proxies.add(proxy)

        return unique_proxies

    @staticmethod
    def download(provider, proxy_type: ProxyType) -> Set[Proxy]:
        logger.debug(f"Downloading Proxies form (URL: {provider['url']}, Type: {proxy_type.name}, Timeout: {provider['timeout']:d})")
        proxies: Set[Proxy] = set()
        with suppress(TimeoutError, ConnectionError, ReadTimeout):
            data = get(provider["url"], timeout=provider["timeout"]).text
            try:
                for proxy in ProxyUtiles.parseAllIPPort(
                        data.splitlines(), proxy_type):
                    proxies.add(proxy)
            except Exception as e:
                logger.error(f"Download Proxy Error: {e.__str__() or e.__repr__()}")
        return proxies

    @staticmethod
    def loadProxyList(config, proxies_file: Path, proxy_type: int) -> Set[Proxy] | None:
        """
        Loads the list of proxies from the given file, and makes sure they are unique.

        Args:
            config: Config with default proxies (used if the file is not found).
            proxies_file: Path to the text file with the list of proxy server addresses (one per line).
            proxy_type: Type of the proxy (1 for HTTP, 4 for SOCKS4, 5 for SOCKS5, 6 for random).

        Returns:
            The list of loaded proxies. None if no proxies were loaded.
        """
        # check proxy type
        if proxy_type not in {4, 5, 1, 0, 6}:
            exit("Socks Type Not Found [4, 5, 1, 0, 6]")
        if proxy_type == 6:
            proxy_type = choice([4, 5, 1])

        # check if file exists, and download default proxies if it doesn't
        if not proxies_file.exists():
            logger.warning("Provided proxy file doesn't exist, creating files and downloading proxies.")
            proxies_file.parent.mkdir(parents=True, exist_ok=True)
            proxies = ProxyManager.DownloadFromConfig(config, proxy_type)

            # write new proxies to file
            with proxies_file.open("w") as file:
                proxies_list_string = ""
                for proxy in proxies:
                    proxies_list_string += (proxy.__str__() + "\n")
                file.write(proxies_list_string)

        # read proxies from file
        proxies = ProxyUtiles.readFromFile(proxies_file)
        if proxies:
            proxies = ProxyManager.get_unique_proxies_from_set(proxies)
            logger.info(f"Loaded {len(proxies)} include_unique_only proxies from file.")
        else:
            proxies = None
            logger.info("Empty proxy file provided, running attack without proxies.")

        return proxies

    @staticmethod
    def validateProxyList(proxies: Set[Proxy],
                          target_ip: str,
                          port: int,
                          mhddos_attack_method: str,
                          target_url: str = None) -> Set[Proxy]:
        if proxies is None or len(proxies) == 0:
            return set()

        n_proxies = len(proxies)
        total_check_cycles = 3
        l4_retries = 1
        l4_timeout = 2
        l4_interval = 0.2
        l7_timeout = 0.01  # no need to check Layer 7 before the attack started
        expected_max_duration_min = math.ceil(float(total_check_cycles * (l4_retries * (l4_timeout + l4_interval) + l7_timeout)) / 60)

        message = f"Checking if the target is reachable through the provided proxies...\n"
        heart = ansi_wrap("♥", color="red")
        message += f"    This may take up to {expected_max_duration_min} min, but will make the attack more effective. Please hold on {heart}"
        print(message)

        check_start_time = perf_counter()
        validated_proxies: Set[Proxy] = set()
        n_validated = Counter(0)
        n_cycle = Counter(1)

        def proxy_check_thread():
            for i in range(total_check_cycles):
                n_cycle.set(i + 1)

                # check if the provided proxies can reach our target
                l4_result, \
                l7_response, \
                l4_proxied_results, \
                l7_proxied_responses = ConnectivityUtils.health_check(target_ip, port,
                                                                      mhddos_attack_method,
                                                                      target_url,
                                                                      list(proxies),
                                                                      layer_4_retries=l4_retries,
                                                                      layer_4_timeout=l4_timeout,
                                                                      layer_4_interval=l4_interval,
                                                                      layer_7_timeout=l7_timeout)

                # grab valid proxies from the results
                for j, proxy in enumerate(proxies):
                    proxied_result = l4_proxied_results[j]
                    if proxied_result.is_alive:
                        validated_proxies.add(proxy)

                    # proxied_response = l7_proxied_responses[j]
                    # if proxied_response:
                    #     validated_proxies_indices.add(proxy)

                # update stats
                n_validated.set(len(validated_proxies))

        # run checks in another thread
        thread = Thread(daemon=True, target=proxy_check_thread)
        thread.start()

        # display waiting notification
        GO_TO_PREVIOUS_LINE = f"\033[A"
        CLEAR_LINE = "\033[K"
        GO_TO_LINE_START = "\r"
        cyclic_periods = CyclicPeriods()
        first_run = True
        while thread.is_alive():
            if int(n_validated) < 1:
                print(f"    Proxy check cycle {int(n_cycle)}/{total_check_cycles}{cyclic_periods}")
            else:
                p_word = "proxies" if int(n_validated) > 1 else "proxy"
                message = f"    Proxy check cycle {int(n_cycle)}/{total_check_cycles} ("
                message += ansi_wrap(f"confirmed {int(n_validated)} {p_word}", color="green")
                message += f"){cyclic_periods}"
                print(message)

            sleep(cyclic_periods.update_interval)

        duration = perf_counter() - check_start_time
        n_validated = int(n_validated)
        if n_validated > 0:
            message = f"    Checked {n_proxies} proxies in {duration:.0f} sec. "
            print(message, end="")
            sleep(2)
            message = ansi_wrap(f"{n_validated} {'proxies are' if n_validated > 1 else 'proxy is'} suitable for the attack.", color="green")
            print(message)
            sleep(2)
        else:
            exit("The target is not reachable through any of the provided proxies. The target may be down.")

        return validated_proxies
