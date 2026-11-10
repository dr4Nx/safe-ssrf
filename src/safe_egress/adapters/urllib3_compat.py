"""A limited urllib3 import replacement backed by SafeFetcher.

This module supports common ``PoolManager().request(...)`` and
``urllib3.request(...)`` call sites. It intentionally does not implement
urllib3's pools, proxies, retry engine, streaming, custom TLS, or connection
objects. Unsupported constructor and request options raise ``PolicyError``
instead of being ignored.

Applications can migrate a supported call site with::

    import safe_egress.urllib3_compat as urllib3

The facade still requires the optional urllib3 dependency for response and
exception types. It is a scoped adapter, not a drop-in replacement for the
full urllib3 package.
"""

from __future__ import annotations

from typing import Any

try:
    import urllib3 as _urllib3
except ImportError as exc:  # pragma: no cover - depends on optional extra
    raise ImportError("urllib3_compat requires the optional 'urllib3' dependency") from exc

from ..errors import PolicyError
from ..policy import FetchPolicy
from .urllib3 import SafeUrllib3Client


exceptions = _urllib3.exceptions
HTTPResponse = _urllib3.response.HTTPResponse
HTTPHeaderDict = _urllib3.response.HTTPHeaderDict


class PoolManager:
    """A policy-bound facade for common ``urllib3.PoolManager`` call sites."""

    def __init__(self, *args: Any, policy: FetchPolicy | None = None, **kwargs: Any) -> None:
        if args or kwargs:
            unsupported = ", ".join(sorted(kwargs))
            if args:
                unsupported = (unsupported + ", " if unsupported else "") + "positional arguments"
            raise PolicyError(f"Unsupported urllib3 PoolManager options: {unsupported}")
        self._client = SafeUrllib3Client(policy=policy)

    def request(self, method: str, url: str, **kwargs: Any) -> HTTPResponse:
        return self._client.request(method, url, **kwargs)

    def urlopen(self, method: str, url: str, **kwargs: Any) -> HTTPResponse:
        """Alias for urllib3's lower-level request method."""
        return self.request(method, url, **kwargs)

    def clear(self) -> None:
        """Compatibility no-op; this facade does not retain connection pools."""

    def close(self) -> None:
        """Compatibility no-op; requests are completed before returning."""

    def __enter__(self) -> PoolManager:
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        del exc_type, exc, traceback
        self.close()


def request(method: str, url: str, **kwargs: Any) -> HTTPResponse:
    """Send one request using a fresh policy-bound client."""
    policy = kwargs.pop("policy", None)
    if policy is not None and not isinstance(policy, FetchPolicy):
        raise PolicyError("policy must be a FetchPolicy")
    return SafeUrllib3Client(policy=policy).request(method, url, **kwargs)


__all__ = [
    "HTTPHeaderDict",
    "HTTPResponse",
    "PoolManager",
    "exceptions",
    "request",
]
