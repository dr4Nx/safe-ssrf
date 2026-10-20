"""Destination policy for safe outbound HTTP fetches."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import math
import re

from .errors import PolicyError


_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def normalize_host(host: str) -> str:
    """Return a canonical hostname or compressed IP literal for comparisons.

    Normalizing before applying host rules prevents spelling differences such
    as uppercase letters, a trailing DNS dot, or Unicode IDNs from bypassing an
    exact allowlist entry.
    """
    if not host or "%" in host:
        raise PolicyError("Invalid host")
    host = host.rstrip(".")
    if not host:
        raise PolicyError("Invalid host")
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        pass
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise PolicyError("Invalid internationalized hostname") from exc
    if len(ascii_host) > 253 or any(not _HOST_LABEL.fullmatch(part) for part in ascii_host.split(".")):
        raise PolicyError("Invalid hostname")
    return ascii_host


@dataclass(frozen=True, slots=True)
class FetchPolicy:
    """Controls which destinations ``SafeFetcher`` may contact.

    ``allowed_hosts=None`` permits any hostname whose resolved addresses are
    globally routable. A supplied set is an exact hostname allowlist; its
    members must still resolve to public addresses unless separately listed in
    ``allowed_private_hosts``. That second setting is an exact exception for
    intentionally trusted internal services. Neither setting supports suffix
    or wildcard matches.
    """

    allowed_hosts: frozenset[str] | None = None
    allowed_private_hosts: frozenset[str] = field(default_factory=frozenset)
    allowed_ports: frozenset[int] = field(default_factory=lambda: frozenset({80, 443}))
    max_redirects: int = 3
    max_response_bytes: int = 5 * 1024 * 1024
    max_request_bytes: int = 5 * 1024 * 1024
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        # Store canonical values so later checks compare like with like.
        if self.allowed_hosts is not None:
            normalized = frozenset(normalize_host(host) for host in self.allowed_hosts)
            object.__setattr__(self, "allowed_hosts", normalized)
        private = frozenset(normalize_host(host) for host in self.allowed_private_hosts)
        object.__setattr__(self, "allowed_private_hosts", private)
        ports = frozenset(self.allowed_ports)
        if not ports or any(
            not isinstance(port, int) or isinstance(port, bool) or port < 1 or port > 65535
            for port in ports
        ):
            raise ValueError("allowed_ports must contain valid TCP port numbers")
        object.__setattr__(self, "allowed_ports", ports)
        if (
            not isinstance(self.max_redirects, int)
            or isinstance(self.max_redirects, bool)
            or self.max_redirects < 0
        ):
            raise ValueError("max_redirects must be a non-negative integer")
        if (
            not isinstance(self.max_response_bytes, int)
            or isinstance(self.max_response_bytes, bool)
            or self.max_response_bytes < 1
        ):
            raise ValueError("max_response_bytes must be a positive integer")
        if (
            not isinstance(self.max_request_bytes, int)
            or isinstance(self.max_request_bytes, bool)
            or self.max_request_bytes < 1
        ):
            raise ValueError("max_request_bytes must be a positive integer")
        if (
            not isinstance(self.timeout_seconds, (int, float))
            or isinstance(self.timeout_seconds, bool)
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be a positive finite number")

    def check_host(self, host: str) -> str:
        """Normalize ``host`` and enforce the optional hostname allowlist."""
        normalized = normalize_host(host)
        if self.allowed_hosts is not None and normalized not in self.allowed_hosts:
            raise PolicyError("Host is not in the configured allowlist")
        return normalized

    def check_port(self, port: int) -> None:
        """Reject ports outside the configured TCP destination set."""
        if port not in self.allowed_ports:
            raise PolicyError("Port is not allowed by the configured policy")

    def permits_private(self, host: str) -> bool:
        """Return whether this exact hostname has the explicit private-host exception."""
        return normalize_host(host) in self.allowed_private_hosts

    @staticmethod
    def is_public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Return whether an IP is globally routable under Python's IANA tables.

        This is an address check, not a guarantee that the destination is
        benign. It keeps non-public and special-use ranges out of ordinary
        fetches; application-specific host allowlists can narrow access more.
        """
        if isinstance(address, ipaddress.IPv6Address):
            # Reject transition/translation forms so embedded IPv4 policy cannot
            # disagree with the address ultimately routed by the network.
            if address.ipv4_mapped is not None or address.sixtofour is not None or address.teredo is not None:
                return False
            if address in ipaddress.ip_network("64:ff9b::/96"):
                return False
            if address in ipaddress.ip_network("64:ff9b:1::/48"):
                return False
        return address.is_global
