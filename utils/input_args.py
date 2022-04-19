import argparse
from typing import List

from pydantic import BaseModel, Field

from MHDDoS.methods.methods import Methods


class Arguments(BaseModel):
    targets: List[str] = Field(default=[])
    config: str = Field(default=None)
    config_fetch_interval: float = Field(default=600)
    attack_methods: List[str] = Field(default=[])
    requests_per_connection: int = 100
    proxies: str = Field(default=None)
    proxies_validation_timeout: float = Field(default=3)
    proxies_fetch_interval: float = Field(default=600)
    no_gui: bool = Field(default=False)
    ignore_geolocation_change: bool = Field(default=False)


def parse_command_line_args() -> Arguments:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "targets",
        nargs="*",
        type=str,
        help="List of targets, separated by spaces",
    )
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        help="URL or local path of a file with attack targets",
    )
    parser.add_argument(
        "--config-fetch-interval",
        type=float,
        default=600,
        help="How often to fetch the targets configuration (in seconds) (default is 600)",
    )
    # parser.add_argument(
    #     "-t",
    #     "--threads",
    #     type=int,
    #     default=-1,
    #     help=f"Total number of threads to run (default is CPU * THREADS_PER_CORE).\n"
    #          f"NOTE: Unused parameter. Kept for compatibility with mhddos_proxy commands. Palyanytsya manages threads automatically.",
    # )
    # parser.add_argument(
    #     "--rpc",
    #     type=int,
    #     default=2000,
    #     help=f"How many requests to send on a single proxy connection (default is 2000)\n"
    #          f"NOTE: Unused argument. Kept for compatibility with mhddos_proxy commands. Palyanytsya keeps the connections alive until they are changes by the configuration re-fetch.",
    # )
    # parser.add_argument(
    #     "--debug",
    #     action="store_true",
    #     default=False,
    #     help=f"Print log as text\n"
    #          f"NOTE: Unused argument. Kept for compatibility with mhddos_proxy commands. Palyanytsya always logs debug info into STDERR.",
    # )
    # parser.add_argument(
    #     "--table",
    #     action="store_true",
    #     default=False,
    #     help="Print log as table\n"
    #          f"NOTE: Unused argument. Kept for compatibility with mhddos_proxy commands. Palyanytsya provides a command-line GUI with attack status by default.",
    # )
    parser.add_argument(
        "--vpn",
        dest="vpn_mode",
        action="store_true",
        default=False,
        help="Disable proxies to use VPN",
    )
    # parser.add_argument(
    #     "--http-methods",
    #     nargs="+",
    #     type=str.upper,
    #     default=["GET", "POST", "STRESS"],
    #     choices=Methods.LAYER7_METHODS,
    #     help="List of HTTP(s) attack methods to use. Default is GET + POST|STRESS",
    # )
    parser.add_argument(
        "-m",
        "--attack-methods",
        nargs="+",
        type=str.upper,
        default=["TCP", "GET", "POST", "STRESS"],
        choices=Methods.ALL_METHODS,
        help="List of MHDDoS attack methods to use. Default is TCP + GET + POST + STRESS",
    )
    parser.add_argument(
        "-r",
        "--requests-per-connection",
        type=int,
        default=100,
        help="Number of requests per single connection when running a Layer 7 attack",
    )
    parser.add_argument(
        "-p",
        "--proxies",
        help="URL or local path to a file with proxies to use",
    )
    parser.add_argument(
        "--proxies-validation-timeout",
        type=float,
        default=3,
        help="How many seconds to wait for the proxy to make a connection (default is 5)"
    )
    parser.add_argument(
        "--proxies-fetch-interval",
        type=float,
        default=600,
        help="How often to fetch the proxies (in seconds) (default is 600)",
    )
    parser.add_argument(
        "--no-gui",
        action="store_true",
        default=False,
        help="Disable the GUI and display live logs from all processes instead",
    )
    parser.add_argument(
        "-g",
        "--ignore-geolocation-change",
        action="store_true",
        default=False,
        help="Do not pause current attacks if the local machine's IP geolocation changes (for example, when VPN disconnects)",
    )
    # parser.add_argument(
    #     "--itarmy",
    #     action="store_true",
    #     default=False,
    # )
    args = parser.parse_args()
    args = Arguments.parse_obj(args.__dict__)

    return args
