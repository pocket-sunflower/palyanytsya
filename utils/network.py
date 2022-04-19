"""Networking-related utilities."""
from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
from typing import List

import validators
from dns.resolver import Resolver
from requests import get, RequestException, ConnectionError
from yarl import URL

from MHDDoS.methods.tools import Tools


class NetworkUtils:
    """Useful functions for working with IPs and domains."""
    
    PLAINTEXT_PUBLIC_IP_ENDPOINTS = [
        "https://api.ipify.org/",
        "https://api.my-ip.io/ip/",
        "https://ip.42.pl/raw/",
        "https://v4.ident.me/",
        "https://ip.seeip.org/"
    ]
    
    JSON_PUBLIC_IP_ENDPOINTS = [
        "https://ipwhois.app/json/",
        "https://ipinfo.io/json/",
    ]

    DNS_RESOLVER = Resolver(configure=False)
    DNS_RESOLVER.nameservers = [
        "1.1.1.1", "1.0.0.1",  # Cloudflare
        "8.8.8.8", "8.8.4.4",  # Google
        "9.9.9.9", "149.112.112.112",  # Quad9
        "208.67.222.222", "208.67.220.220",  # OpenDNS
        "8.26.56.26", "8.20.247.20",  # Comodo Secure DNS
        "185.228.168.9", "185.228.169.9",  # CleanBrowsing
        "76.76.19.19", "76.223.122.150",  # Alternate DNS
        "94.140.14.14", "94.140.15.15",  # AdGuard DNS
    ]
    
    @staticmethod
    def get_my_ip(timeout: float = 0.5) -> str:
        """
        Returns public IP of the current machine.
        Raises ConnectionError if public IP cannot be determined.
        """
        for endpoint in NetworkUtils.PLAINTEXT_PUBLIC_IP_ENDPOINTS:
            with suppress(RequestException):
                ip = get(endpoint, timeout=timeout).content.decode('utf8')
                return ip

        for endpoint in NetworkUtils.JSON_PUBLIC_IP_ENDPOINTS:
            with suppress(RequestException, KeyError):
                ip = get(endpoint, timeout=timeout).json()["ip"]
                return ip

        raise ConnectionError("Public IP could not be identified. This machine may be offline.")

    @staticmethod
    def resolve_ip(domain: str, return_all_ips: bool = False) -> str | List[str]:
        """
        Resolves IP from the given domain name.

        Args:
            domain: Domain to resolve the IP of.
            return_all_ips: If set to False (default), only the first resolved IP address is returned.
                If set to True, all resolved IP addresses for this domain are returned in a list.

        Returns:
            Domain's IP or list of IPs (depending on 'return_all_ips' argument's value).
        """
        if validators.ipv4(domain):
            return [domain] if return_all_ips else domain

        domain = Tools.ensure_http_present(domain)
        host = URL(domain).host

        answer = NetworkUtils.DNS_RESOLVER.resolve(host)
        all_ips = [x.to_text() for x in answer]

        return all_ips if return_all_ips else all_ips[0]


@dataclass(slots=True, order=True, frozen=True)
class IPGeolocationData:
    ip: str
    country: str
    region: str
    city: str
    isp: str

    def __str__(self):
        return f"{self.ip} ({self.city}, {self.country})"

    @staticmethod
    def get_for_my_ip(timeout: float = 1) -> IPGeolocationData:
        """
        Tries to retrieve geolocation data for the local machine's IP.
        Raises ConnectionError if it fails.

        Returns:
            IPGeolocationData.
        """
        local_ip = NetworkUtils.get_my_ip(timeout)
        return IPGeolocationData.get_for_ip(local_ip, timeout)

    @staticmethod
    def get_for_ip(ip: str, timeout: float = 1) -> IPGeolocationData:
        """
        Tries to retrieve geolocation data for the given IP.
        Raises ConnectionError if it fails.

        Args:
            ip: IP to get the data for.
            timeout: Request timeout.

        Returns:
            IPGeolocationData.
        """
        unknown_value = "unknown"

        with suppress(Exception), get(f"https://ipwhois.app/json/{ip}/", timeout=timeout) as response:
            ip_info_dict = response.json()
            return IPGeolocationData(
                ip=ip,
                country=ip_info_dict.get("country", unknown_value),
                region=ip_info_dict.get("region", unknown_value),
                city=ip_info_dict.get("city", unknown_value),
                isp=ip_info_dict.get("isp", unknown_value),
            )

        raise ConnectionError(f"Geolocation info for IP '{ip}' could not be retrieved.")

