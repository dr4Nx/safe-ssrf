"""Destination policy for safe outbound HTTP fetches."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import math
import re

from .errors import PolicyError


# Address exceptions for Python versions whose ``ipaddress`` tables differ
# from the intended public-unicast rule.
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_NON_GLOBAL_SPECIAL_NETWORKS = (
    ipaddress.ip_network("192.88.99.0/24"),  # deprecated 6to4 relay anycast
    ipaddress.ip_network("100:0:0:1::/64"),  # dummy IPv6 prefix
    ipaddress.ip_network("5f00::/16"),  # SRv6 SIDs are not globally reachable
)
_IPV6_TRANSLATION_NETWORKS = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
)
# IANA lists this address as globally reachable; older Python tables can say otherwise.
_GLOBAL_SPECIAL_ADDRESSES = frozenset({ipaddress.ip_address("2001:1::3")})
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
    invalid_label = any(not _HOST_LABEL.fullmatch(part) for part in ascii_host.split("."))
    if len(ascii_host) > 253 or invalid_label:
        raise PolicyError("Invalid hostname")
    return ascii_host


def _normalize_allowed_ips(
    values: frozenset[str | ipaddress.IPv4Address | ipaddress.IPv6Address],
) -> frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Parse configured IP exceptions once, when the policy is constructed."""
    if isinstance(values, (str, bytes)):
        raise ValueError("allowed_ips must be a collection of IP addresses")
    try:
        addresses = tuple(values)
    except TypeError as exc:
        raise ValueError("allowed_ips must contain valid IP addresses") from exc
    if any(
        not isinstance(value, (str, ipaddress.IPv4Address, ipaddress.IPv6Address))
        for value in addresses
    ):
        raise ValueError("allowed_ips must contain valid IP addresses")
    try:
        parsed = frozenset(ipaddress.ip_address(value) for value in addresses)
    except ValueError as exc:
        raise ValueError("allowed_ips must contain valid IP addresses") from exc
    if any(
        isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None
        for address in parsed
    ):
        raise ValueError("allowed_ips cannot contain scoped IPv6 addresses")
    return parsed


def _normalize_sensitive_headers(values: frozenset[str]) -> frozenset[str]:
    """Validate custom redirect-sensitive header names and lowercase them."""
    if isinstance(values, str):
        raise ValueError("additional_sensitive_headers must be a collection of header names")
    try:
        names = frozenset(values)
    except TypeError as exc:
        raise ValueError("additional_sensitive_headers must be a collection of header names") from exc
    if any(not isinstance(name, str) or not _HEADER_NAME.fullmatch(name) for name in names):
        raise ValueError("additional_sensitive_headers contains an invalid HTTP header name")
    return frozenset(name.lower() for name in names)


def _validate_integer_limit(name: str, value: int, *, minimum: int) -> None:
    """Validate a non-negative count or positive byte limit."""
    qualifier = "non-negative" if minimum == 0 else "positive"
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValueError(f"{name} must be a {qualifier} integer")


@dataclass(frozen=True, slots=True)
class FetchPolicy:
    """Controls which destinations ``SafeFetcher`` may contact.

    With the defaults, any hostname is allowed only if it resolves to a public
    address, and only ports 80 and 443 are allowed. ``allowed_hosts`` narrows
    that to exact hostnames; it does not make private addresses safe. An exact
    IP in ``allowed_ips`` is an intentional exception that can allow private
    addresses, including localhost. Multicast is always denied. Every DNS
    answer is checked, so a mixed or rebound hostname cannot slip through.
    Host and IP rules do not support wildcard or suffix matching.

    To allow one internal service, pair its exact hostname with its exact IP::

        FetchPolicy(
            allowed_hosts=frozenset({"files.example"}),
            allowed_ips=frozenset({"10.20.30.40"}),
        )

    Explicit ``allowed_ips`` entries can permit private or loopback peers. Do
    this only for a service the application intentionally trusts. Cross-origin
    redirects remove standard credential headers, including common API-key
    headers; add application-specific secret header names with
    ``additional_sensitive_headers``.
    """

    # Destination rules. Hosts are exact names; IP entries are explicit
    # exceptions for trusted private services.
    allowed_hosts: frozenset[str] | None = None
    allowed_ips: frozenset[str | ipaddress.IPv4Address | ipaddress.IPv6Address] = field(
        default_factory=frozenset
    )
    allowed_ports: frozenset[int] = field(default_factory=lambda: frozenset({80, 443}))

    # Resource and redirect limits.
    max_redirects: int = 3
    max_response_bytes: int = 5 * 1024 * 1024
    max_request_bytes: int = 5 * 1024 * 1024
    timeout_seconds: float = 5.0

    # Extra secret headers to strip when a redirect changes origin.
    additional_sensitive_headers: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        """Validate settings and store normalized immutable values."""
        if self.allowed_hosts is not None:
            hosts = frozenset(normalize_host(host) for host in self.allowed_hosts)
            object.__setattr__(self, "allowed_hosts", hosts)

        object.__setattr__(self, "allowed_ips", _normalize_allowed_ips(self.allowed_ips))
        object.__setattr__(
            self,
            "additional_sensitive_headers",
            _normalize_sensitive_headers(self.additional_sensitive_headers),
        )

        ports = frozenset(self.allowed_ports)
        if not ports or any(
            not isinstance(port, int) or isinstance(port, bool) or port < 1 or port > 65535
            for port in ports
        ):
            raise ValueError("allowed_ports must contain valid TCP port numbers")
        object.__setattr__(self, "allowed_ports", ports)

        _validate_integer_limit("max_redirects", self.max_redirects, minimum=0)
        _validate_integer_limit("max_response_bytes", self.max_response_bytes, minimum=1)
        _validate_integer_limit("max_request_bytes", self.max_request_bytes, minimum=1)
        if (
            not isinstance(self.timeout_seconds, (int, float))
            or isinstance(self.timeout_seconds, bool)
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be a positive finite number")

    def check_host(self, host: str) -> str:
        """Normalize and optionally allowlist a host; IP safety is checked later."""
        normalized = normalize_host(host)
        if self.allowed_hosts is not None and normalized not in self.allowed_hosts:
            raise PolicyError("Host is not in the configured allowlist")
        return normalized

    def check_port(self, port: int) -> None:
        """Reject ports outside the configured TCP destination set."""
        if port not in self.allowed_ports:
            raise PolicyError("Port is not allowed by the configured policy")

    def permits_address(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Apply the resolved-IP rule after the hostname has been checked.

        Exact ``allowed_ips`` entries deliberately override the public-only
        default. Multicast is the one address class that cannot be allowlisted.
        """
        if address.is_multicast:
            return False
        if address in self.allowed_ips:
            return True
        return self.is_public_address(address)

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
        # Localhost (127.0.0.0/8 and ::1) is always denied by the default
        # public-address rule. An exact allowed_ips entry can override this in
        # permits_address() when a trusted local fixture/service is intended.
        if address.is_loopback:
            return False

        # Link-local ranges include cloud metadata addresses such as
        # 169.254.169.254. They are not public destinations.
        if address.is_link_local:
            return False

        # HTTP destinations must be unicast. ipaddress.is_global alone may
        # classify multicast as global on some Python versions.
        if address.is_multicast:
            return False

        if any(
            address.version == network.version and address in network
            for network in _NON_GLOBAL_SPECIAL_NETWORKS
        ):
            return False

        if isinstance(address, ipaddress.IPv6Address):
            # Reject IPv6 forms that can route to an embedded IPv4 address.
            if (
                address.ipv4_mapped is not None
                or address.sixtofour is not None
                or address.teredo is not None
            ):
                return False
            if any(address in network for network in _IPV6_TRANSLATION_NETWORKS):
                return False

        # Python's global table can lag IANA. Preserve this known globally
        # reachable special address on versions with an outdated table.
        if address in _GLOBAL_SPECIAL_ADDRESSES:
            return True

        # This final check rejects private, reserved, unspecified, and other
        # non-global addresses. In particular, private ranges fail here even
        # when they are not loopback or link-local.
        return address.is_global
