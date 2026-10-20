"""A small Requests-shaped facade backed only by SafeRequestsSession.

This module supports common ``requests.get/post/...`` call sites and the
``requests.Session`` constructor so applications can replace their import
with ``import safe_egress.requests_compat as requests``. It is not a complete
implementation of the Requests module: unsupported transport features remain
fail-closed in :class:`SafeRequestsSession`.
"""

from __future__ import annotations

from typing import Any

try:
    import requests as _requests
except ImportError as exc:  # pragma: no cover - depends on optional extra
    raise ImportError("requests_compat requires the optional 'requests' dependency") from exc

from .requests_adapter import SafeRequestsSession


Session = SafeRequestsSession
Request = _requests.Request
Response = _requests.Response
exceptions = _requests.exceptions


def request(method: str, url: str, **kwargs: Any) -> Response:
    """Send one request using a fresh policy-bound session."""
    with SafeRequestsSession() as session:
        return session.request(method, url, **kwargs)


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
    "Request",
    "Response",
    "SafeRequestsSession",
    "Session",
    "delete",
    "exceptions",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
    "request",
]
