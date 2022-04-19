from __future__ import annotations

import re
import time

import validators
from yarl import URL

from MHDDoS.methods.tools import Tools

from utils.network import NetworkUtils

L4_PROTOCOLS = ["tcp", "udp", "dns"]
L7_PROTOCOLS = ["ssh", "https", "http", "smtp"]

REGEX_FLAGS = re.RegexFlag.UNICODE | re.RegexFlag.IGNORECASE

REGEX_PROTOCOL = rf"(?:{'|'.join(L4_PROTOCOLS + L7_PROTOCOLS)})"
REGEX_DOMAIN_URL = r"(?:[a-zA-Z0-9\-]+)(?:\.[a-zA-Z0-9\-]+)*(?:\.[a-zA-Z\-][a-zA-Z0-9\-]+)[/]?"
REGEX_IP = r"(?:(?:(?:2[5][0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})\.(?:2[5][0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})\." \
           r"(?:2[5][0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})\.(?:2[5][0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2}))){1}"
REGEX_PORT = r"(?:6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})"
REGEX_COLON_PORT = fr"(?::{REGEX_PORT})"
REGEX_TARGET = rf"(?:{REGEX_PROTOCOL}:\/\/)?(?:(?:{REGEX_DOMAIN_URL}|{REGEX_IP}))(?:{REGEX_COLON_PORT})?"

REGEX_PROTOCOL = re.compile(REGEX_PROTOCOL, REGEX_FLAGS)
REGEX_DOMAIN_URL = re.compile(REGEX_DOMAIN_URL, REGEX_FLAGS)
REGEX_IP = re.compile(REGEX_IP, REGEX_FLAGS)
REGEX_COLON_PORT = re.compile(REGEX_COLON_PORT, REGEX_FLAGS)
REGEX_TARGET = re.compile(REGEX_TARGET, REGEX_FLAGS)

DEFAULT_PORT = 443
DEFAULT_L4_PROTOCOL = "tcp"
DEFAULT_L7_PROTOCOL = "https"


class Target:
    """
    Utility class representing an attack target.
    """
    url: URL = None
    ip: str = None
    port: int = None
    protocol: str = None

    def __init__(self,
                 address: str,
                 port: int = None,
                 protocol: str = None):
        # handle port
        if port is None:
            port = DEFAULT_PORT
        self.port = port

        # handle address
        address.removesuffix("/")
        if REGEX_IP.match(address):
            if protocol is None:
                protocol = DEFAULT_L4_PROTOCOL
            self.ip = address
            self.url = URL(f"{protocol}://{self.ip}:{self.port}")
        elif REGEX_DOMAIN_URL.match(address):
            if protocol is None:
                protocol = DEFAULT_L7_PROTOCOL
            address = f"{protocol}://{address}"
            # ensure protocol in URL
            address = Tools.ensure_http_present(address)
            # ensure port in URL
            address.removesuffix("/")
            if len(address.split(":")) >= 1:
                address = f"{address}:{port}"
            address += "/"
            self.url = URL(address)
            # if address is URL, find the associated IP
            self.ip = NetworkUtils.resolve_ip(self.url.host)

        # save protocol
        self.protocol = protocol

    def __str__(self):
        string = ""
        if self.url is not None:
            url = self.url
            string += f"{url.scheme}://{url.host}:{url.port}{url.path}"
        elif self.ip is not None:
            if self.protocol is not None:
                string += f"{self.protocol}://"
            string += f"{self.ip}"
            if self.port is not None:
                string += f":{self.port}"

        return string

    def __eq__(self, other):
        if not isinstance(other, Target):
            return
        return self.ip == other.ip and self.url == other.url and self.port == self.port

    @property
    def is_valid(self) -> bool:
        """
        A valid target will have a valid IP, and (optionally) a URL.
        """
        if self.ip is None:
            return False
        if not validators.ipv4(self.ip):
            return False
        if self.port < 1 or self.port > 65535:
            return False

        return True

    @property
    def is_layer_7(self) -> bool:
        """Checks if the target uses Layer 7 protocol."""
        return self.is_valid and (self.protocol in L7_PROTOCOLS)

    @property
    def is_layer_4(self) -> bool:
        """Checks if the target uses Layer 4 protocol."""
        return self.is_valid and (self.protocol in L4_PROTOCOLS)

    @staticmethod
    def parse_from_string(string: str) -> Target | None:
        """
        Tries to parse a valid target from a string.

        Args:
            string: String to parse from.

        Returns:
            Target if it was successfully parsed, None otherwise.
        """

        target_matches = REGEX_TARGET.findall(string)
        if len(target_matches) == 0:
            return None

        # we have data for a target; create it and populate with what we can find
        target_match = target_matches[0]

        # parse protocol using regex
        protocol_matches = REGEX_PROTOCOL.findall(target_match)
        protocol = None
        if len(protocol_matches) > 0:
            protocol = protocol_matches[0]

        # parse ip using regex
        ip_matches = REGEX_IP.findall(target_match)
        ip = None
        if len(ip_matches) > 0:
            ip = ip_matches[0]

        # parse URL using regex
        url_matches = REGEX_DOMAIN_URL.findall(target_match)
        url = None
        if len(url_matches) > 0:
            url = url_matches[0]

        # parse port using regex
        port_matches = REGEX_COLON_PORT.findall(target_match)
        port = None
        if len(port_matches) > 0:
            port = int(port_matches[0].removeprefix(":"))

        # # parse protocol using regex
        # protocol_matches = REGEX_PROTOCOL.findall(target_match)
        # if len(protocol_matches) > 0:
        #     target.protocol = int(protocol_matches[0].removesuffix("://"))

        parsed_target = Target(
            address=ip if ip is not None else url,
            port=port,
            protocol=protocol
        )

        return parsed_target
