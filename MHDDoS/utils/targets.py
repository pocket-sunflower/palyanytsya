from __future__ import annotations

import re

import validators
from yarl import URL

from MHDDoS.methods.tools import Tools

REGEX_FLAGS = re.RegexFlag.UNICODE | re.RegexFlag.IGNORECASE

REGEX_PROTOCOL = r"(?:tcp|udp|ssh|dns|https|http|smtp)"
REGEX_DOMAIN_URL = r"(?:http[s]?:\/\/)?(?:[a-zA-Z0-9\-]+)(?:\.[a-zA-Z0-9\-]+)*(?:\.[a-zA-Z\-][a-zA-Z0-9\-]+)[/]?"
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
# DEFAULT_L4_PROTOCOL = "TCP"
# DEFAULT_L7_PROTOCOL = "HTTPS"


class Target:
    """
    Utility class representing an attack target.
    """
    url: URL = None
    ip: str = None
    port: int = None
    # protocol: str = None

    def __init__(self,
                 address: str,
                 port: int = DEFAULT_PORT):
        if validators.ipv4(address):
            self.ip = address
        elif validators.url(address):
            # ensure protocol in URL
            address = Tools.ensure_http_present(address)
            # ensure port in URL
            if len(address.split(":")) == 1:
                address = f"{address}:{port}"
            self.url = URL(address)
            # if address is URL, find the associated IP
            self.ip = Tools.get_ip(self.url.host)

        self.port = port

    def __str__(self):
        string = ""
        if self.url is not None:
            string += f"{self.url}"
        elif self.ip is not None:
            string += f"{self.ip}"

        if self.port is not None:
            string += f":{self.port}"

        return string

    def is_valid(self) -> bool:
        """
        A valid target will have a valid IP, and (optionally) a URL.
        """
        if self.ip is None:
            return False
        if not validators.ipv4(self.ip):
            return False
        if not validators.url(self.url):
            return False
        if self.port < 1 or self.port > 65535:
            return False

        return True

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
        target = Target("")

        # parse ip using regex
        ip_matches = REGEX_IP.findall(target_match)
        if len(ip_matches) > 0:
            target.ip = ip_matches[0]

        # parse URL using regex
        url_matches = REGEX_DOMAIN_URL.findall(target_match)
        if len(url_matches) > 0:
            url = Tools.ensure_http_present(url_matches[0])
            target.url = URL(url)

        # parse port using regex
        port_matches = REGEX_COLON_PORT.findall(target_match)
        if len(port_matches) > 0:
            target.port = int(port_matches[0].removeprefix(":"))

        # # parse protocol using regex
        # protocol_matches = REGEX_PROTOCOL.findall(target_match)
        # if len(protocol_matches) > 0:
        #     target.protocol = int(protocol_matches[0].removesuffix("://"))

        return target
