"""Synchronous HTTP requests with destination checks bound to the socket."""

from __future__ import annotations

from dataclasses import dataclass
import http.client
import ipaddress
import math
import re
import socket
import ssl
import time
import zlib
from typing import Mapping
from urllib.parse import quote, urljoin, urlsplit

from .errors import FetchError, PolicyError, RedirectLimitError, RequestTooLargeError, ResponseTooLargeError
from .defaults import DEFAULT_POLICY
from .policy import FetchPolicy, normalize_host

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_FORBIDDEN_HEADERS = frozenset(
    {"host", "proxy-authorization", "proxy-connection", "content-length", "transfer-encoding"}
)
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_NUMERIC_IPV4_COMPONENT = r"(?:[0-9]+|0[xX][0-9a-fA-F]+)"
_NONCANONICAL_IPV4_HOST = re.compile(
    rf"^{_NUMERIC_IPV4_COMPONENT}(?:\.{_NUMERIC_IPV4_COMPONENT}){{0,3}}$"
)


def _inflate_bounded(data: bytes, window_bits: int, limit: int) -> tuple[bytes, bytes]:
    """Inflate one zlib/gzip member without producing more than ``limit`` bytes."""
    decoder = zlib.decompressobj(window_bits)
    output = bytearray()
    pending = data
    while True:
        remaining = limit + 1 - len(output)
        if remaining <= 0:
            raise ResponseTooLargeError("Decoded response body exceeded the configured byte limit")
        try:
            output.extend(decoder.decompress(pending, remaining))
        except zlib.error as exc:
            raise FetchError("The response used an invalid content encoding") from exc
        if len(output) > limit:
            raise ResponseTooLargeError("Decoded response body exceeded the configured byte limit")
        pending = decoder.unconsumed_tail
        if not pending:
            break
    if not decoder.eof:
        raise FetchError("The response contained an incomplete compressed body")
    return bytes(output), decoder.unused_data


def _decode_response_body(
    body: bytes,
    headers: tuple[tuple[str, str], ...],
    limit: int,
) -> tuple[bytes, tuple[tuple[str, str], ...]]:
    """Decode supported content codings under the response size limit.

    SafeFetcher requests identity encoding, but a server may still return a
    compressed entity. Decode gzip/deflate incrementally so callers receive
    ordinary response bytes without allowing a small compressed body to
    expand past the configured cap.
    """
    codings = [
        coding.strip().lower()
        for name, value in headers
        if name.lower() == "content-encoding"
        for coding in value.split(",")
        if coding.strip()
    ]
    codings = [coding for coding in codings if coding != "identity"]
    if not codings:
        return body, headers
    if any(coding not in {"gzip", "x-gzip", "deflate"} for coding in codings):
        raise PolicyError("The response used an unsupported content encoding")

    decoded = body
    for coding in reversed(codings):
        if coding in {"gzip", "x-gzip"}:
            remaining = decoded
            members = bytearray()
            while remaining:
                member, remaining = _inflate_bounded(
                    remaining,
                    zlib.MAX_WBITS | 16,
                    limit - len(members),
                )
                members.extend(member)
                if len(members) > limit:
                    raise ResponseTooLargeError("Decoded response body exceeded the configured byte limit")
            decoded = bytes(members)
        else:
            try:
                decoded, trailing = _inflate_bounded(decoded, zlib.MAX_WBITS, limit)
            except ResponseTooLargeError:
                raise
            except FetchError:
                # Some servers emit raw DEFLATE despite the HTTP deflate
                # coding's zlib-wrapped format. Accept it only if it forms a
                # complete stream and remains within the same output limit.
                decoded, trailing = _inflate_bounded(decoded, -zlib.MAX_WBITS, limit)
            if trailing:
                raise FetchError("The response contained trailing compressed data")
        if len(decoded) > limit:
            raise ResponseTooLargeError("Decoded response body exceeded the configured byte limit")

    decoded_headers = tuple(
        (name, value)
        for name, value in headers
        if name.lower() not in {"content-encoding", "content-length"}
    ) + (("Content-Length", str(len(decoded))),)
    return decoded, decoded_headers


@dataclass(frozen=True, slots=True)
class FetchResponse:
    """A fully buffered response body and the URL that produced it.

    ``history`` contains each URL that redirected to the final ``url``. Bodies
    are buffered so the configured maximum response size can be enforced.
    """

    status_code: int
    headers: tuple[tuple[str, str], ...]
    content: bytes
    url: str
    history: tuple[str, ...]
    method: str = "GET"
    peer_ip: str | None = None


@dataclass(frozen=True, slots=True)
class _Target:
    """Parsed request fields used after URL validation."""

    url: str
    scheme: str
    host: str
    port: int
    request_target: str

    @property
    def origin(self) -> tuple[str, str, int]:
        return (self.scheme, self.host, self.port)


@dataclass(frozen=True, slots=True)
class ValidatedDestination:
    """One parsed HTTP(S) destination and every approved numeric address.

    Transport adapters can use this result to pin a non-SafeFetcher client to
    the checked addresses. They must connect to one of ``addresses`` directly;
    using ``url`` with a client that resolves the hostname again reopens the
    DNS-rebinding race.
    """

    url: str
    scheme: str
    host: str
    port: int
    request_target: str
    addresses: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]

    @property
    def origin(self) -> tuple[str, str, int]:
        return (self.scheme, self.host, self.port)


class _PinnedSocketMixin:
    """Dial a checked numeric IP without resolving the hostname a second time.

    For HTTPS, the connection object still receives the original hostname, so
    it can use that name for TLS SNI and certificate verification.
    """

    _safe_egress_ip: ipaddress.IPv4Address | ipaddress.IPv6Address

    def _create_pinned_connection(
        self,
        address: tuple[str, int],
        timeout: float | None = None,
        source_address: tuple[str, int] | None = None,
    ) -> socket.socket:
        ip = self._safe_egress_ip
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            if source_address is not None:
                sock.bind(source_address)
            sockaddr: tuple[object, ...]
            if ip.version == 6:
                sockaddr = (ip.compressed, address[1], 0, 0)
            else:
                sockaddr = (ip.compressed, address[1])
            sock.connect(sockaddr)  # Numeric address only: no second DNS lookup.
            return sock
        except BaseException:
            sock.close()
            raise


class _PinnedHTTPConnection(_PinnedSocketMixin, http.client.HTTPConnection):
    """HTTPConnection that connects to the IP already approved by policy."""

    def __init__(self, host: str, port: int, pinned_ip: ipaddress.IPv4Address | ipaddress.IPv6Address, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._safe_egress_ip = pinned_ip
        # HTTPConnection stores socket.create_connection on the instance. Set
        # our pinned implementation after its initializer to avoid a DNS lookup.
        self._create_connection = self._create_pinned_connection


class _PinnedHTTPSConnection(_PinnedSocketMixin, http.client.HTTPSConnection):
    """HTTPSConnection that pins TCP to an approved IP but verifies the host."""

    def __init__(
        self,
        host: str,
        port: int,
        pinned_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._safe_egress_ip = pinned_ip
        self._create_connection = self._create_pinned_connection


class _ConnectionAttemptError(Exception):
    """A connection failed before the HTTP request was written."""


class SafeFetcher:
    """Fetch HTTP(S) URLs after validating and pinning their destinations.

    For each URL, the fetcher parses and normalizes the destination, checks the
    port and hostname policy, resolves the hostname, validates every returned
    IP, then connects to one of those checked numeric IPs. Redirects repeat
    these checks. This order prevents a DNS answer from changing between the
    security check and the connection (DNS rebinding).

    The fetcher makes direct TCP connections and does not consult proxy
    environment variables. It supports bounded HTTP methods and request bodies,
    and buffers responses up to the configured size limit. It supports only
    HTTP(S), not arbitrary protocols, proxies, or streaming.
    """

    def __init__(self, policy: FetchPolicy | None = None) -> None:
        self.policy = policy if policy is not None else DEFAULT_POLICY
        self._ssl_context = ssl.create_default_context()

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        policy: FetchPolicy | None = None,
    ) -> FetchResponse:
        """Fetch ``url`` with policy checks before every connection."""
        return self.request("GET", url, headers=headers, policy=policy)

    def validate_destination(
        self,
        url: str,
        *,
        policy: FetchPolicy | None = None,
    ) -> ValidatedDestination:
        """Parse and authorize a URL before another transport connects.

        Every DNS answer is checked and returned as a numeric address. A
        caller that uses another HTTP client must pin its connection to the
        returned address rather than ask that client to resolve ``url`` again.
        This method does not open a connection or follow redirects.
        """
        active_policy = self.policy if policy is None else policy
        if not isinstance(active_policy, FetchPolicy):
            raise PolicyError("policy must be a FetchPolicy")
        target = self._parse_target(url)
        active_policy.check_port(target.port)
        normalized_host = active_policy.check_host(target.host)
        if active_policy is self.policy:
            addresses = self._resolve_and_check(normalized_host, target.port)
        else:
            addresses = self._resolve_and_check(
                normalized_host,
                target.port,
                policy=active_policy,
            )
        return ValidatedDestination(
            url=target.url,
            scheme=target.scheme,
            host=normalized_host,
            port=target.port,
            request_target=target.request_target,
            addresses=addresses,
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        timeout_seconds: float | None = None,
        follow_redirects: bool = True,
        policy: FetchPolicy | None = None,
    ) -> FetchResponse:
        """Send one bounded HTTP request, rechecking each redirect destination.

        A redirect is treated as a new untrusted URL: its scheme, port, host,
        and DNS results are checked from scratch. Sensitive headers are also
        removed when a redirect changes origin. A supplied ``policy`` replaces
        the fetcher's configured policy for this complete request chain.
        """
        if not isinstance(method, str) or not _HEADER_NAME.fullmatch(method):
            raise PolicyError("HTTP method must be a valid ASCII token")
        if body is not None and not isinstance(body, bytes):
            raise PolicyError("Request body must be bytes or None")
        active_policy = self.policy if policy is None else policy
        if not isinstance(active_policy, FetchPolicy):
            raise PolicyError("policy must be a FetchPolicy")
        if body is not None and len(body) > active_policy.max_request_bytes:
            raise RequestTooLargeError("Request body exceeded the configured byte limit")
        if timeout_seconds is not None and (not math.isfinite(timeout_seconds) or timeout_seconds <= 0):
            raise PolicyError("Request timeout must be a positive finite number")
        effective_timeout = min(active_policy.timeout_seconds, timeout_seconds or active_policy.timeout_seconds)
        policy_options = {} if active_policy is self.policy else {"policy": active_policy}
        request_headers = self._prepare_headers(headers or {})
        current_url = url
        history: list[str] = []
        previous_origin: tuple[str, str, int] | None = None
        current_body = body

        for redirect_count in range(active_policy.max_redirects + 1):
            # Parse and authorize each hop independently; never assume the
            # redirect target has the same safety properties as the first URL.
            target = self.validate_destination(current_url, policy=active_policy)
            if previous_origin is not None and target.origin != previous_origin:
                # Do not forward credentials or origin metadata to a different
                # host/scheme/port named by a redirect response.
                request_headers = self._strip_origin_credentials(request_headers, active_policy)

            # validate_destination checks all DNS answers; _send receives a
            # checked numeric address so the TCP layer cannot resolve again.
            addresses = target.addresses
            response = None
            selected_address = None
            connection_error: _ConnectionAttemptError | None = None
            connect_deadline = time.monotonic() + effective_timeout
            attempted_connection = False
            for address in addresses:
                connect_timeout = connect_deadline - time.monotonic()
                if connect_timeout <= 0:
                    break
                connect_options = (
                    {"connect_timeout_seconds": connect_timeout}
                    if attempted_connection
                    else {}
                )
                try:
                    response = self._send(
                        target,
                        address,
                        request_headers,
                        method=method,
                        body=current_body,
                        timeout_seconds=effective_timeout,
                        **connect_options,
                        **policy_options,
                    )
                except _ConnectionAttemptError as exc:
                    connection_error = exc
                    attempted_connection = True
                    continue
                selected_address = address
                break
            if response is None or selected_address is None:
                raise FetchError("Could not connect to any approved destination address") from connection_error
            location = self._header(response.headers, "location")
            if response.status_code not in _REDIRECT_STATUSES or location is None or not follow_redirects:
                return FetchResponse(
                    status_code=response.status_code,
                    headers=response.headers,
                    content=response.content,
                    url=target.url,
                    history=tuple(history),
                    method=method,
                    peer_ip=str(selected_address),
                )
            if redirect_count >= active_policy.max_redirects:
                raise RedirectLimitError("The response exceeded the configured redirect limit")
            next_url = urljoin(target.url, location)
            history.append(target.url)
            previous_origin = target.origin
            method_changed = False
            if response.status_code == 303 and method.upper() != "HEAD":
                method, current_body = "GET", None
                method_changed = True
            elif response.status_code in {301, 302} and method.upper() == "POST":
                method, current_body = "GET", None
                method_changed = True
            if method_changed:
                request_headers = {
                    name: value
                    for name, value in request_headers.items()
                    if name.lower() not in {"content-length", "content-type", "content-encoding", "transfer-encoding"}
                }
            current_url = next_url

        raise RedirectLimitError("The response exceeded the configured redirect limit")

    @staticmethod
    def _parse_target(url: str) -> _Target:
        """Accept only unambiguous HTTP(S) URLs and split out request fields."""
        if not isinstance(url, str) or not url:
            raise PolicyError("URL must be a non-empty string")
        if url != url.strip() or any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F for char in url):
            raise PolicyError("Whitespace and control characters are not allowed in URLs")
        if "\\" in url or "#" in url:
            # Backslashes can be interpreted differently by URL parsers, while
            # fragments are client-side and should not affect an HTTP request.
            raise PolicyError("Backslashes and fragments are not allowed in URLs")
        try:
            parsed = urlsplit(url)
            scheme = parsed.scheme.lower()
            if scheme not in {"http", "https"}:
                raise PolicyError("Only HTTP and HTTPS URLs are supported")
            if not parsed.netloc or "@" in parsed.netloc:
                # Userinfo makes host interpretation confusing and can hide the
                # actual network destination from a reviewer.
                raise PolicyError("A host is required and URL credentials are not accepted")
            if "%" in parsed.netloc:
                raise PolicyError("Percent-encoded host syntax is not accepted")
            raw_host = parsed.hostname
            if raw_host is None:
                raise PolicyError("A host is required")
            host = normalize_host(raw_host)
            try:
                ipaddress.ip_address(host)
            except ValueError:
                if _NONCANONICAL_IPV4_HOST.fullmatch(host):
                    raise PolicyError("Non-canonical numeric IP address is not accepted")
            explicit_port = parsed.port
            port = explicit_port if explicit_port is not None else (443 if scheme == "https" else 80)
        except ValueError as exc:
            raise PolicyError("Malformed URL") from exc
        request_path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
        if parsed.query:
            request_path += "?" + quote(parsed.query, safe="/%?@!$&'()*+,;=:-._~")
        return _Target(url=url, scheme=scheme, host=host, port=port, request_target=request_path)

    def _resolve_and_check(
        self, host: str, port: int, *, policy: FetchPolicy | None = None
    ) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
        """Resolve ``host`` and reject it if any possible address is non-public.

        Checking every answer prevents a hostname with a mixed public/private
        DNS response from passing policy. IP literals skip DNS but go through
        the same address check. The exact-host private exception is deliberate
        and should only be configured for hostnames the caller controls.
        """
        try:
            literal = ipaddress.ip_address(host)
            addresses = (literal,)
        except ValueError:
            try:
                records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            except OSError as exc:
                raise PolicyError("Hostname resolution failed") from exc
            parsed_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
            for record in records:
                try:
                    address_text = record[4][0]
                    if "%" in address_text:
                        raise ValueError("Scoped IPv6 address")
                    parsed_addresses.append(ipaddress.ip_address(address_text))
                except (IndexError, ValueError) as exc:
                    raise PolicyError("Resolver returned an unsupported address") from exc
            addresses = tuple(dict.fromkeys(parsed_addresses))
            if not addresses:
                raise PolicyError("Hostname resolved to no usable addresses")

        active_policy = self.policy if policy is None else policy
        if any(
            not active_policy.permits_address(address) for address in addresses
        ):
            raise PolicyError("Hostname resolved to a non-public address")
        return addresses

    def _send(
        self,
        target: ValidatedDestination,
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
        headers: Mapping[str, str],
        *,
        method: str = "GET",
        body: bytes | None = None,
        timeout_seconds: float | None = None,
        connect_timeout_seconds: float | None = None,
        policy: FetchPolicy | None = None,
    ) -> FetchResponse:
        """Open one connection to the approved IP and read a bounded response."""
        connection_type = _PinnedHTTPSConnection if target.scheme == "https" else _PinnedHTTPConnection
        timeout = timeout_seconds or self.policy.timeout_seconds
        connect_timeout = timeout
        if connect_timeout_seconds is not None:
            if not math.isfinite(connect_timeout_seconds) or connect_timeout_seconds <= 0:
                raise PolicyError("Connection timeout must be a positive finite number")
            connect_timeout = min(timeout, connect_timeout_seconds)
        if target.scheme == "https":
            connection = connection_type(
                target.host, target.port, address, timeout, self._ssl_context
            )
        else:
            connection = connection_type(target.host, target.port, address, timeout)
        try:
            try:
                # Connect separately so another already-validated address can
                # be tried only when no HTTP request bytes could have been sent.
                connection.timeout = connect_timeout
                connection.connect()
            except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
                raise _ConnectionAttemptError("Connection to the approved address failed") from exc
            if connection.sock is not None:
                connection.sock.settimeout(timeout)
            connection.timeout = timeout
            connection.request(method, target.request_target, body=body, headers=dict(headers))
            response = connection.getresponse()
            # Read one byte above the limit so an oversized response can be
            # detected without buffering an unbounded body.
            max_response_bytes = (policy or self.policy).max_response_bytes
            body = response.read(max_response_bytes + 1)
            if len(body) > max_response_bytes:
                raise ResponseTooLargeError("Response body exceeded the configured byte limit")
            headers = tuple(response.getheaders())
            body, headers = _decode_response_body(body, headers, max_response_bytes)
            return FetchResponse(
                status_code=response.status,
                headers=headers,
                content=body,
                url=target.url,
                history=(),
                method=method,
            )
        except FetchError:
            raise
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            raise FetchError("The outbound request failed") from exc
        finally:
            connection.close()

    @staticmethod
    def _prepare_headers(headers: Mapping[str, str]) -> dict[str, str]:
        """Validate caller headers and set connection-managed defaults."""
        prepared: dict[str, str] = {}
        seen: set[str] = set()
        for name, value in headers.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise PolicyError("HTTP header names and values must be strings")
            normalized = name.lower()
            if normalized in seen:
                raise PolicyError("Duplicate HTTP header names are not accepted")
            seen.add(normalized)
            if normalized in _FORBIDDEN_HEADERS or normalized.startswith("proxy-"):
                raise PolicyError("Host and proxy headers are managed by SafeFetcher")
            if not _HEADER_NAME.fullmatch(name):
                raise PolicyError("Invalid HTTP header name")
            if any((ord(char) < 0x20 and char != "\t") or ord(char) == 0x7F for char in value):
                raise PolicyError("Invalid HTTP header value")
            try:
                value.encode("latin-1")
            except UnicodeEncodeError as exc:
                raise PolicyError("HTTP header values must be Latin-1 encodable") from exc
            prepared[name] = value
        prepared = {
            name: value
            for name, value in prepared.items()
            if name.lower() not in {"connection", "accept-encoding"}
        }
        prepared["Connection"] = "close"
        prepared["Accept-Encoding"] = "identity"
        return prepared

    @staticmethod
    def _strip_origin_credentials(
        headers: Mapping[str, str], policy: FetchPolicy
    ) -> dict[str, str]:
        """Remove headers that should not cross to a redirected origin."""
        denied = policy.redirect_sensitive_headers
        return {name: value for name, value in headers.items() if name.lower() not in denied}

    @staticmethod
    def _header(headers: tuple[tuple[str, str], ...], name: str) -> str | None:
        """Look up an HTTP response header without case sensitivity."""
        for key, value in headers:
            if key.lower() == name:
                return value
        return None
