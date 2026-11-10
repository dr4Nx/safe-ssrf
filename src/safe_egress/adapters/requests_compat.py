"""A small Requests-shaped facade backed only by SafeRequestsSession.

This module supports common ``requests.get/post/...`` call sites and the
``requests.Session`` constructor so applications can replace their import
with ``import safe_egress.requests_compat as requests``. It is not a complete
implementation of the Requests module: unsupported transport features remain
fail-closed in :class:`SafeRequestsSession`.
"""

from __future__ import annotations

import ipaddress
from typing import Any

try:
    import requests as _requests
except ImportError as exc:  # pragma: no cover - depends on optional extra
    raise ImportError("requests_compat requires the optional 'requests' dependency") from exc

from .requests import SafeRequestsSession
from ..policy import FetchPolicy, normalize_host


Session = SafeRequestsSession
Request = _requests.Request
PreparedRequest = _requests.PreparedRequest
Response = _requests.Response
exceptions = _requests.exceptions
# Requests exposes these exception classes at both ``requests`` and
# ``requests.exceptions``. Preserve those common imports for aliased modules.
ConnectTimeout = _requests.ConnectTimeout
ConnectionError = _requests.ConnectionError
FileModeWarning = _requests.FileModeWarning
HTTPError = _requests.HTTPError
JSONDecodeError = _requests.JSONDecodeError
ReadTimeout = _requests.ReadTimeout
RequestException = _requests.RequestException
Timeout = _requests.Timeout
TooManyRedirects = _requests.TooManyRedirects
URLRequired = _requests.URLRequired


def Allow(*destinations: str) -> FetchPolicy:
    """Build a policy allowing only these exact hostnames and IP addresses.

    Hostnames still must resolve only to globally routable addresses. A
    private IP literal is permitted only when that exact address is listed;
    passing both a hostname and private IP allows that hostname to use that
    one private peer. No wildcard or suffix matching is supported.

    Example::

        import safe_egress.requests_compat as requests

        policy = requests.Allow("1.2.3.4", "www.mytrusted.server")
        response = requests.get(url, policy=policy)
    """
    hosts: set[str] = set()
    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for destination in destinations:
        if not isinstance(destination, str):
            raise ValueError("Allow destinations must be hostname or IP strings")
        host = normalize_host(destination)
        hosts.add(host)
        try:
            addresses.add(ipaddress.ip_address(host))
        except ValueError:
            continue
    return FetchPolicy(
        allowed_hosts=frozenset(hosts),
        allowed_ips=frozenset(addresses),
    )


def request(method: str, url: str, **kwargs: Any) -> Response:
    """Send one request using a fresh policy-bound session."""
    with SafeRequestsSession() as session:
        return session.request(method, url, **kwargs)


def session() -> SafeRequestsSession:
    """Return a persistent policy-bound session, matching ``requests.session()``."""
    return SafeRequestsSession()


def get(url: str, params: Any = None, **kwargs: Any) -> Response:
    return request("get", url, params=params, **kwargs)


def options(url: str, **kwargs: Any) -> Response:
    return request("options", url, **kwargs)


def head(url: str, **kwargs: Any) -> Response:
    kwargs.setdefault("allow_redirects", False)
    return request("head", url, **kwargs)


def post(url: str, data: Any = None, json: Any = None, **kwargs: Any) -> Response:
    return request("post", url, data=data, json=json, **kwargs)


def put(url: str, data: Any = None, **kwargs: Any) -> Response:
    return request("put", url, data=data, **kwargs)


def patch(url: str, data: Any = None, **kwargs: Any) -> Response:
    return request("patch", url, data=data, **kwargs)


def delete(url: str, **kwargs: Any) -> Response:
    return request("delete", url, **kwargs)


__all__ = [
    "Allow",
    "ConnectTimeout",
    "ConnectionError",
    "FileModeWarning",
    "FetchPolicy",
    "HTTPError",
    "PreparedRequest",
    "JSONDecodeError",
    "Request",
    "RequestException",
    "ReadTimeout",
    "Response",
    "SafeRequestsSession",
    "Session",
    "Timeout",
    "TooManyRedirects",
    "URLRequired",
    "delete",
    "exceptions",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
    "request",
    "session",
]
