"""SSRF-hardened synchronous wrapper for ``curl-cffi`` requests.

The wrapper validates and pins each HTTP(S) hop before curl-cffi opens a
connection. It exposes a small requests-like API (``request``, ``get``,
``post``, and ``head``) and returns curl-cffi response objects. It creates a
fresh curl-cffi session for each hop so cached DNS and pooled connections
cannot outlive the checked destination.

This adapter is optional and currently supports buffered byte request bodies,
bounded response bodies, direct connections, and caller supplied headers. It
does not implement curl-cffi's async, websocket, proxy, upload, streaming,
session-cookie-jar, or impersonation APIs.
"""

from __future__ import annotations

import ipaddress
import math
import os
import re
import socket
import sys
from collections.abc import Mapping
from importlib.metadata import version as distribution_version
from typing import Any
from urllib.parse import urljoin

from ...client import SafeFetcher, ValidatedDestination
from ...errors import (
    FetchError,
    PolicyError,
    RedirectLimitError,
    RequestTooLargeError,
    ResponseTooLargeError,
)
from ...policy import FetchPolicy

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_CURL_CFFI_VERSION = "0.15.0"
_CURL_OPENSOCKETFUNCTION = 20163  # CURLOPTTYPE_FUNCTIONPOINT + 163
_CURLSOCKTYPE_IPCXN = 0
_CURL_SOCKET_BAD = -1


def _require_curl_cffi_version(installed_version: str) -> None:
    if installed_version != _CURL_CFFI_VERSION:
        raise ImportError(
            f"SafeCurlCffiSession currently supports curl-cffi=={_CURL_CFFI_VERSION}; "
            f"found {installed_version}"
        )


def _load_curl_cffi() -> tuple[Any, Any, Any, int]:
    """Load optional curl-cffi symbols only when the adapter makes a request."""
    try:
        from curl_cffi import requests as curl_requests
        from curl_cffi.const import CurlOpt
        from curl_cffi import curl as curl_module
        from curl_cffi.curl import CURL_WRITEFUNC_ERROR
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise ImportError(
            "SafeCurlCffiSession requires the optional 'curl-cffi' dependency"
        ) from exc
    _require_curl_cffi_version(distribution_version("curl-cffi"))
    return curl_requests, CurlOpt, curl_module, CURL_WRITEFUNC_ERROR


def _decode_curl_socket_address(ffi: Any, address: Any) -> tuple[int, int, int, int, ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    """Decode libcurl's ``curl_sockaddr`` using its documented field layout.

    curl-cffi 0.15 does not declare this struct in its CFFI interface. The
    three integer fields and addrlen occupy the first 16 bytes; the remaining
    bytes are the platform ``sockaddr``. This adapter supports POSIX sockaddr
    layouts, whose IPv4/IPv6 address and port offsets are stable here.
    """
    if not address:
        raise ValueError("libcurl supplied a null socket address")
    prefix = bytes(ffi.buffer(address, 16))
    if len(prefix) != 16:
        raise ValueError("libcurl supplied a truncated socket address")
    family = int.from_bytes(prefix[0:4], byteorder=sys.byteorder, signed=True)
    socktype = int.from_bytes(prefix[4:8], byteorder=sys.byteorder, signed=True)
    protocol = int.from_bytes(prefix[8:12], byteorder=sys.byteorder, signed=True)
    address_length = int.from_bytes(prefix[12:16], byteorder=sys.byteorder)
    if address_length < 8 or address_length > 128:
        raise ValueError("libcurl supplied an invalid sockaddr length")
    sockaddr = bytes(ffi.buffer(address, 16 + address_length)[16:])
    port = int.from_bytes(sockaddr[2:4], byteorder="big")
    if family == socket.AF_INET and address_length >= 8:
        peer = ipaddress.IPv4Address(sockaddr[4:8])
    elif family == socket.AF_INET6 and address_length >= 24:
        peer = ipaddress.IPv6Address(sockaddr[8:24])
    else:
        raise ValueError("libcurl supplied an unsupported address family")
    return family, socktype, protocol, address_length, peer, port


class SafeCurlCffiSession:
    """Requests-like synchronous client backed by curl-cffi.

    The caller can override the destination policy for an individual request.
    Redirects are followed manually so each new URL is resolved, checked, and
    pinned before curl-cffi sends it. Caller-provided ``Host`` and proxy
    headers are rejected, proxies and environment-derived settings are off,
    and curl's observed peer IP must be one of the addresses that was checked.

    Unlike curl-cffi's regular ``Session``, this wrapper does not maintain a
    cookie jar or reuse connections between calls. Pass cookies explicitly in
    a request's headers when needed; cross-origin redirects strip cookie and
    other sensitive headers according to the active policy.
    """

    def __init__(
        self,
        policy: FetchPolicy | None = None,
        *,
        fetcher: SafeFetcher | None = None,
    ) -> None:
        if fetcher is not None and policy is not None:
            raise ValueError("Pass either fetcher or policy, not both")
        self.fetcher = fetcher or SafeFetcher(policy)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        data: bytes | None = None,
        timeout: float | None = None,
        follow_redirects: bool = True,
        policy: FetchPolicy | None = None,
    ) -> Any:
        """Send a bounded request, validating and pinning every redirect hop."""
        if not isinstance(method, str) or not _HEADER_NAME.fullmatch(method):
            raise PolicyError("HTTP method must be a valid ASCII token")
        method = method.upper()
        if data is not None and not isinstance(data, bytes):
            raise PolicyError("Request body must be bytes or None")
        if not isinstance(follow_redirects, bool):
            raise PolicyError("follow_redirects must be a bool")

        active_policy = self.fetcher.policy if policy is None else policy
        if not isinstance(active_policy, FetchPolicy):
            raise PolicyError("policy must be a FetchPolicy")
        if data is not None and len(data) > active_policy.max_request_bytes:
            raise RequestTooLargeError("Request body exceeded the configured byte limit")
        if timeout is not None and (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise PolicyError("Request timeout must be a positive finite number")
        effective_timeout = min(
            active_policy.timeout_seconds,
            timeout if timeout is not None else active_policy.timeout_seconds,
        )
        current_headers = self.fetcher._prepare_headers(headers or {})
        current_url = url
        current_method = method
        current_data = data
        previous_origin: tuple[str, str, int] | None = None
        history: list[Any] = []

        curl_requests, curl_opt, curl_module, write_error = _load_curl_cffi()
        for redirect_count in range(active_policy.max_redirects + 1):
            destination = self.fetcher.validate_destination(
                current_url,
                policy=active_policy,
            )
            if previous_origin is not None and destination.origin != previous_origin:
                current_headers = self.fetcher._strip_origin_credentials(
                    current_headers,
                    active_policy,
                )

            resolved_url = self._resolved_url(destination)
            resolve_rule = self._resolve_rule(destination)
            response_body = bytearray()
            overflow = False
            invalid_peer = False
            open_socket_error: Exception | None = None

            def open_checked_socket(
                _client_data: Any,
                purpose: int,
                address: Any,
            ) -> int:
                """Create a socket only for an address already approved by policy."""
                nonlocal invalid_peer, open_socket_error
                try:
                    family, socktype, protocol, _length, peer, peer_port = (
                        _decode_curl_socket_address(curl_module.ffi, address)
                    )
                    if (
                        purpose != _CURLSOCKTYPE_IPCXN
                        or peer not in destination.addresses
                        or peer_port != destination.port
                        or socktype != socket.SOCK_STREAM
                        or protocol not in {0, socket.IPPROTO_TCP}
                    ):
                        invalid_peer = True
                        return bad_socket
                    sock = socket.socket(family, socktype, protocol)
                    try:
                        return sock.detach()
                    except Exception:
                        sock.close()
                        raise
                except Exception as exc:
                    open_socket_error = exc
                    return bad_socket

            def check_peer_before_request(
                _client_data: Any,
                primary_ip: Any,
                _local_ip: Any,
                primary_port: int,
                _local_port: int,
            ) -> int:
                """Reject an unexpected peer before libcurl sends HTTP bytes."""
                nonlocal invalid_peer
                try:
                    peer = ipaddress.ip_address(
                        curl_module.ffi.string(primary_ip).decode("ascii")
                    )
                    allowed = peer in destination.addresses and primary_port == destination.port
                except (AttributeError, UnicodeDecodeError, TypeError, ValueError):
                    allowed = False
                if not allowed:
                    invalid_peer = True
                    # libcurl's CURL_PREREQFUNC_ABORT value.
                    return 1
                return 0

            prereq_callback = curl_module.ffi.callback(
                "int(void *, char *, char *, int, int)"
            )(check_peer_before_request)
            if os.name == "nt":
                # On Windows curl_socket_t is SOCKET (uintptr_t), while POSIX
                # libcurl uses an int file descriptor.
                socket_result_type = "uintptr_t"
                bad_socket = int(curl_module.ffi.cast(socket_result_type, -1))
            else:
                socket_result_type = "int"
                bad_socket = _CURL_SOCKET_BAD

            opensocket_callback = curl_module.ffi.callback(
                f"{socket_result_type}(void *, int, void *)"
            )(open_checked_socket)

            class _PeerCheckedCurl(curl_module.Curl):
                """Bridge callback options not handled by curl-cffi 0.15 setopt."""

                def setopt(self, option: Any, value: Any) -> int:
                    if option in {curl_opt.PREREQFUNCTION, _CURL_OPENSOCKETFUNCTION}:
                        callbacks = getattr(self, "_safe_egress_callbacks", None)
                        if callbacks is None:
                            callbacks = self._safe_egress_callbacks = []
                        callbacks.append(value)
                        pointer = curl_module.ffi.cast("void *", value)
                        result = curl_module.lib._curl_easy_setopt(
                            self._curl, option, pointer
                        )
                        self._check_error(result, "setopt", option, value)
                        return result
                    return super().setopt(option, value)

            def collect(chunk: bytes) -> int:
                nonlocal overflow
                if len(response_body) + len(chunk) > active_policy.max_response_bytes:
                    overflow = True
                    return write_error
                response_body.extend(chunk)
                return len(chunk)

            # Session curl_options are applied after curl-cffi's own URL and
            # redirect settings. A new session for every hop also avoids its
            # retained DNS and connection caches across policy checks.
            curl_options = {
                curl_opt.PREREQFUNCTION: prereq_callback,
                _CURL_OPENSOCKETFUNCTION: opensocket_callback,
            }
            if resolve_rule is not None:
                curl_options[curl_opt.RESOLVE] = [resolve_rule]

            with curl_requests.Session(
                curl=_PeerCheckedCurl(),
                use_thread_local_curl=False,
                trust_env=False,
                proxies={},
                allow_redirects=False,
                retry=0,
                discard_cookies=True,
                curl_options=curl_options,
            ) as session:
                try:
                    response = session.request(
                        current_method,
                        resolved_url,
                        data=current_data,
                        headers=current_headers,
                        timeout=effective_timeout,
                        allow_redirects=False,
                        accept_encoding="identity",
                        content_callback=collect,
                    )
                except Exception:
                    if invalid_peer:
                        raise FetchError(
                            "curl-cffi encountered a peer outside the validated DNS results"
                        )
                    if open_socket_error is not None:
                        raise FetchError(
                            "curl-cffi could not create a policy-checked socket"
                        ) from open_socket_error
                    if overflow:
                        raise ResponseTooLargeError(
                            "Response body exceeded the configured byte limit"
                        )
                    raise

            if overflow:
                raise ResponseTooLargeError(
                    "Response body exceeded the configured byte limit"
                )
            response.content = bytes(response_body)
            self._check_peer(response, destination)
            response.url = resolved_url
            response.history = history

            location = response.headers.get("Location")
            if (
                not follow_redirects
                or response.status_code not in _REDIRECT_STATUSES
                or not location
            ):
                return response
            if redirect_count >= active_policy.max_redirects:
                raise RedirectLimitError("The response exceeded the configured redirect limit")

            history.append(response)
            next_url = urljoin(resolved_url, location)
            previous_origin = destination.origin
            current_url = next_url

            if response.status_code == 303 and current_method != "HEAD":
                current_method, current_data = "GET", None
            elif response.status_code == 302 and current_method != "HEAD":
                current_method, current_data = "GET", None
            elif response.status_code == 301 and current_method == "POST":
                current_method, current_data = "GET", None
            if current_data is None:
                current_headers = {
                    name: value
                    for name, value in current_headers.items()
                    if name.lower() not in {"content-type", "content-encoding"}
                }

        raise RedirectLimitError("The response exceeded the configured redirect limit")

    def get(self, url: str, **kwargs: Any) -> Any:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Any:
        return self.request("HEAD", url, **kwargs)

    def close(self) -> None:
        """The adapter creates and closes a curl-cffi session for every hop."""
        return None

    def __enter__(self) -> SafeCurlCffiSession:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @staticmethod
    def _resolved_url(destination: ValidatedDestination) -> str:
        host = destination.host
        if ":" in host:
            host = f"[{host}]"
        return f"{destination.scheme}://{host}:{destination.port}{destination.request_target}"

    @staticmethod
    def _resolve_rule(destination: ValidatedDestination) -> str | None:
        # Literal addresses are already the exact destination. Avoid asking
        # older curl-impersonate builds to parse an IPv6 literal as a RESOLVE
        # hostname; the policy check has already authorized the literal.
        try:
            ipaddress.ip_address(destination.host)
            return None
        except ValueError:
            pass
        host = destination.host
        addresses: list[str] = []
        for address in destination.addresses:
            value = address.compressed
            if isinstance(address, ipaddress.IPv6Address):
                value = f"[{value}]"
            addresses.append(value)
        return f"{host}:{destination.port}:{','.join(addresses)}"

    @staticmethod
    def _check_peer(response: Any, destination: ValidatedDestination) -> None:
        peer = getattr(response, "primary_ip", None)
        try:
            peer_ip = ipaddress.ip_address(peer)
        except (TypeError, ValueError) as exc:
            raise FetchError("curl-cffi did not report a valid connected peer IP") from exc
        if peer_ip not in destination.addresses:
            raise FetchError("curl-cffi connected to an address outside the validated DNS results")


__all__ = ["SafeCurlCffiSession"]
