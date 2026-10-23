"""Argument smuggling checks for arguments marked ``kind: url`` or ``kind: path``.

URL rules: http or https only, no userinfo, host must be on the tenant's
egress allowlist, and literal IPs (including decimal, hex and octal forms)
may never be loopback, private, link-local (cloud metadata lives at
169.254.169.254), multicast, reserved or unspecified.

Path rules: relative only, no ``..`` segments, no drive letters, no NUL,
no backslashes, no percent-encoded dots or slashes, and the path itself
(as the upstream will see it) must sit inside the tenant's root, for
example ``data/handbook.txt`` when the root is ``data``. The gateway does
not join the root onto the path, because the upstream would not either:
checking a different string than the one forwarded is how path filters
get bypassed.

Hostnames are not resolved (the gateway may run offline). That means DNS
rebinding is out of scope here; the egress allowlist is the real control.
"""

from __future__ import annotations

import ipaddress
import posixpath
import re
from urllib.parse import urlsplit

from .errors import GateBlocked

BLOCKED_HOSTNAMES = {"localhost", "metadata.google.internal", "metadata", "instance-data"}

_NUM = re.compile(r"(0x[0-9a-fA-F]+|\d+)")


def _part(p: str) -> int:
    if p.lower().startswith("0x"):
        return int(p, 16)
    if len(p) > 1 and p.startswith("0"):
        return int(p, 8)
    return int(p)


def parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse a host the way permissive URL libraries do, including 0x7f000001 and 2130706433."""
    h = host.strip("[]")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    parts = h.split(".")
    if not (1 <= len(parts) <= 4) or not all(_NUM.fullmatch(p) for p in parts):
        return None
    try:
        nums = [_part(p) for p in parts]
    except ValueError:  # e.g. "08" is not valid octal
        return None
    if any(n > 255 for n in nums[:-1]):
        return None
    value = 0
    for n in nums[:-1]:
        value = value * 256 + n
    value = value * (256 ** (5 - len(nums))) + nums[-1] if len(nums) > 1 else nums[0]
    if len(nums) > 1 and nums[-1] >= 256 ** (5 - len(nums)):
        return None
    if 0 <= value < 2**32:
        return ipaddress.IPv4Address(value)
    return None


def ip_is_internal(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    # "not global" also covers shared address space (100.64.0.0/10), benchmarking
    # ranges, documentation ranges and similar addresses that never belong to a
    # public website.
    return (ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified or not ip.is_global)


def host_allowed(host: str, allow: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for entry in allow:
        entry = entry.lower()
        if entry.startswith("*."):
            if host.endswith(entry[1:]) and host != entry[2:]:
                return True
        elif host == entry:
            return True
    return False


def check_url(value: str, egress_allow: list[str], arg: str = "url") -> None:
    if not isinstance(value, str):
        raise GateBlocked("argguard", f"{arg}: must be a string")
    if any(c in value for c in "\r\n\t\x00 "):
        raise GateBlocked("argguard", f"{arg}: whitespace or control characters in URL")
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"}:
        raise GateBlocked("argguard", f"{arg}: scheme {parts.scheme or 'none'} not allowed")
    if "@" in parts.netloc:
        raise GateBlocked("argguard", f"{arg}: userinfo in URL not allowed")
    try:
        host = (parts.hostname or "").lower()
        parts.port  # raises ValueError on a malformed port
    except ValueError:
        raise GateBlocked("argguard", f"{arg}: malformed host") from None
    if not host:
        raise GateBlocked("argguard", f"{arg}: URL has no host")
    ip = parse_ip(host)
    if ip is not None and ip_is_internal(ip):
        raise GateBlocked("argguard", f"{arg}: internal address {ip} (SSRF)", {"host": host})
    if host.rstrip(".") in BLOCKED_HOSTNAMES or host.endswith(".localhost") or host.endswith(".internal"):
        raise GateBlocked("argguard", f"{arg}: internal hostname {host} (SSRF)", {"host": host})
    if not host_allowed(host, egress_allow):
        raise GateBlocked("argguard", f"{arg}: host {host} not on egress allowlist", {"host": host})


def check_path(value: str, root: str, arg: str = "path") -> str:
    if not isinstance(value, str) or not value:
        raise GateBlocked("argguard", f"{arg}: must be a non-empty string")
    if "\x00" in value or "\\" in value:
        raise GateBlocked("argguard", f"{arg}: NUL or backslash in path")
    if value.startswith("/") or re.match(r"^[A-Za-z]:", value) or value.startswith("~"):
        raise GateBlocked("argguard", f"{arg}: absolute or home path not allowed")
    if ".." in value.split("/"):
        raise GateBlocked("argguard", f"{arg}: path traversal (..)")
    low = value.lower()
    if "%2e" in low or "%2f" in low or "%5c" in low:
        raise GateBlocked("argguard", f"{arg}: encoded path characters not allowed")
    root = posixpath.normpath(root.strip("/")) if root.strip("/") else "."
    normalised = posixpath.normpath(value)
    if root != "." and not (normalised == root or normalised.startswith(root + "/")):
        raise GateBlocked("argguard", f"{arg}: path is outside the tenant root {root}/")
    return normalised
