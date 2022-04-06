"""
List of attack methods supported by MHDDoS.
"""
import re
from typing import Set


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

    WHICH_SUPPORT_PROXIES: Set[str] = {"MINECRAFT", "MCBOT", "TCP", *LAYER7_METHODS}
    WHICH_SUPPORT_REFLECTORS: Set[str] = {"NTP", "DNS", "RDP", "CHAR", "MEM", "ARD"}
    WHICH_REQUIRE_RAW_SOCKETS: Set[str] = {"NTP", "DNS", "RDP", "CHAR", "MEM", "ARD", "SYN"}


class Patterns:
    LAYER7_METHOD = re.compile(rf"{'|'.join(Methods.LAYER7_METHODS)}")
    LAYER4_METHOD = re.compile(rf"{'|'.join(Methods.LAYER4_METHODS)}")
    ANY_METHOD = re.compile(rf"{LAYER7_METHOD.pattern}|{LAYER4_METHOD.pattern}")
