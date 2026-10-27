"""Destination policy for safe outbound HTTP fetches."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import math
import re

from .errors import PolicyError


_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_NON_GLOBAL_SPECIAL_NETWORKS = (
    ipaddress.ip_network("192.88.99.0/24"),  # deprecated 6to4 relay anycast
    ipaddress.ip_network("100:0:0:1::/64"),  # dummy IPv6 prefix
    ipaddress.ip_network("5f00::/16"),  # SRv6 SIDs are not globally reachable
)
_GLOBAL_SPECIAL_ADDRESSES = frozenset(
    {ipaddress.ip_address("2001:1::3")}  # DNS-SD Service Registration Anycast
)
_DEFAULT_REDIRECT_SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "cookie2",
        "origin",
        "referer",
        "api-key",
        "x-api-key",
        "api-secret",
        "client-secret",
        "x-api-token",
        "x-api-secret",
        "x-auth-token",
        "x-authentication-token",
        "x-access-token",
        "x-client-token",
        "x-client-secret",
        "x-csrf-token",
        "x-csrftoken",
        "x-xsrf-token",
        "x-refresh-token",
        "x-id-token",
        "x-session-token",
        "x-vault-token",
        "x-consul-token",
        "x-aws-ec2-metadata-token",
        "x-amz-security-token",
        "x-goog-api-key",
    }
)


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
    members must still resolve to public addresses unless an address is listed
    in ``allowed_ips``. Multicast addresses are never permitted, including
    through ``allowed_ips``. Every DNS answer is checked independently, so a
    hostname cannot be rebound to an unlisted private address. Neither host
    nor address settings support suffix or wildcard matches. Cross-origin
    redirects remove standard credential headers, including common API-key
    headers; add
    application-specific secret header names with ``additional_sensitive_headers``.
    """

    allowed_hosts: frozenset[str] | None = None
    allowed_ips: frozenset[str | ipaddress.IPv4Address | ipaddress.IPv6Address] = field(
        default_factory=frozenset
    )
    allowed_ports: frozenset[int] = field(default_factory=lambda: frozenset({80, 443}))
    max_redirects: int = 3
    max_response_bytes: int = 5 * 1024 * 1024
    max_request_bytes: int = 5 * 1024 * 1024
    timeout_seconds: float = 5.0
    additional_sensitive_headers: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        # Store canonical values so later checks compare like with like.
        if self.allowed_hosts is not None:
            normalized = frozenset(normalize_host(host) for host in self.allowed_hosts)
            object.__setattr__(self, "allowed_hosts", normalized)
        if isinstance(self.allowed_ips, (str, bytes)):
            raise ValueError("allowed_ips must be a collection of IP addresses")
        try:
            raw_allowed_ips = tuple(self.allowed_ips)
        except TypeError as exc:
            raise ValueError("allowed_ips must contain valid IP addresses") from exc
        if any(
            not isinstance(
                address,
                (str, ipaddress.IPv4Address, ipaddress.IPv6Address),
            )
            for address in raw_allowed_ips
        ):
            raise ValueError("allowed_ips must contain valid IP addresses")
        try:
            allowed_ips = frozenset(ipaddress.ip_address(address) for address in raw_allowed_ips)
        except ValueError as exc:
            raise ValueError("allowed_ips must contain valid IP addresses") from exc
        if any(
            isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None
            for address in allowed_ips
        ):
            raise ValueError("allowed_ips cannot contain scoped IPv6 addresses")
        object.__setattr__(self, "allowed_ips", allowed_ips)
        if isinstance(self.additional_sensitive_headers, str):
            raise ValueError("additional_sensitive_headers must be a collection of header names")
        try:
            sensitive_headers = frozenset(self.additional_sensitive_headers)
        except TypeError as exc:
            raise ValueError("additional_sensitive_headers must be a collection of header names") from exc
        if any(
            not isinstance(name, str) or not _HEADER_NAME.fullmatch(name)
            for name in sensitive_headers
        ):
            raise ValueError("additional_sensitive_headers contains an invalid HTTP header name")
        object.__setattr__(
            self,
            "additional_sensitive_headers",
            frozenset(name.lower() for name in sensitive_headers),
        )
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

    def permits_address(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Check the public rule or exact IP exception; multicast is always denied."""
        if address.is_multicast:
            return False
        return self.is_public_address(address) or address in self.allowed_ips

    @property
    def redirect_sensitive_headers(self) -> frozenset[str]:
        """Header names stripped from requests redirected across origins."""
        return _DEFAULT_REDIRECT_SENSITIVE_HEADERS | self.additional_sensitive_headers

    @staticmethod
    def is_public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Check global reachability with corrections for stale stdlib tables.

        This is an address check, not a guarantee that the destination is
        benign. It keeps non-public and special-use ranges out of ordinary
        fetches; application-specific host allowlists can narrow access more.
        """
        # ipaddress.is_global is also True for multicast addresses. An HTTP
        # destination must be unicast; multicast is not a globally reachable
        # public host and should never pass the default egress policy.
        if address.is_multicast:
            return False
        if any(
            address.version == network.version and address in network
            for network in _NON_GLOBAL_SPECIAL_NETWORKS
        ):
            return False
        if isinstance(address, ipaddress.IPv6Address):
            # Reject transition/translation forms so embedded IPv4 policy cannot
            # disagree with the address ultimately routed by the network.
            if address.ipv4_mapped is not None or address.sixtofour is not None or address.teredo is not None:
                return False
            if address in ipaddress.ip_network("64:ff9b::/96"):
                return False
            if address in ipaddress.ip_network("64:ff9b:1::/48"):
                return False
        # Python's global table can lag new IANA special-purpose allocations.
        # Keep this explicit global-reachability assignment usable on older
        # supported Python versions where it is covered by a broader private
        # prefix.
        if address in _GLOBAL_SPECIAL_ADDRESSES:
            return True
        return address.is_global
