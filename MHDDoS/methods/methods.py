"""
List of attack methods supported by MHDDoS.
"""

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
