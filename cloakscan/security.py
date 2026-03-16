from __future__ import annotations

from functools import lru_cache
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}
DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
}


def _is_non_public_ip(value: ipaddress._BaseAddress) -> bool:
    return not value.is_global


@lru_cache(maxsize=512)
def _resolve_host_ips(hostname: str) -> tuple[str, ...]:
    try:
        results = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return ()

    addresses: set[str] = set()
    for result in results:
        sockaddr = result[4]
        if sockaddr:
            addresses.add(str(sockaddr[0]))
    return tuple(sorted(addresses))


def validate_remote_url(url: str, allow_unsafe: bool = False) -> str | None:
    if allow_unsafe:
        return None

    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        rendered = parsed.scheme or "none"
        return f"Blocked unsupported URL scheme '{rendered}'"

    hostname = parsed.hostname
    if not hostname:
        return "Blocked URL without hostname"

    normalized_hostname = hostname.rstrip(".").lower()
    if normalized_hostname in _BLOCKED_HOSTNAMES or normalized_hostname.endswith(".localhost"):
        return f"Blocked local hostname '{hostname}'"

    try:
        ip = ipaddress.ip_address(normalized_hostname)
    except ValueError:
        resolved_ips = _resolve_host_ips(normalized_hostname)
        if not resolved_ips:
            return None

        blocked_ips = [
            candidate
            for candidate in resolved_ips
            if _is_non_public_ip(ipaddress.ip_address(candidate))
        ]
        if blocked_ips:
            blocked = ", ".join(blocked_ips[:3])
            return f"Blocked non-public destination '{hostname}' ({blocked})"
        return None

    if _is_non_public_ip(ip):
        return f"Blocked non-public destination '{hostname}'"
    return None
