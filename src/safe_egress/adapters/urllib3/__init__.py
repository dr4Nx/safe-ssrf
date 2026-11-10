"""urllib3 client and import facade backed by SafeFetcher.

This is a facade for common ``PoolManager.request`` call sites, not a
``PoolManager`` subclass. It intentionally does not expose pools, connection
objects, proxies, custom TLS, retry configuration, chunked uploads, or
streaming. Redirects are handled and checked by SafeFetcher.
"""

from __future__ import annotations

from io import BytesIO
import json as json_module
from typing import Any

try:
    import urllib3
    from urllib3.response import HTTPHeaderDict, HTTPResponse
except ImportError as exc:  # pragma: no cover - depends on optional extra
    raise ImportError("SafeUrllib3Client requires the optional 'urllib3' dependency") from exc

from ...client import SafeFetcher
from ...errors import FetchError, PolicyError, RequestTooLargeError
from ...policy import FetchPolicy


class SafeUrllib3Error(urllib3.exceptions.HTTPError):
    """A urllib3-compatible base error for policy or transport rejections."""


class SafeUrllib3Client:
    """Use a small subset of the ``PoolManager.request`` interface safely.

    Supported options are ``body``, ``headers``, ``json``, ``redirect``,
    ``timeout`` (a positive number), ``preload_content=True``, and
    ``decode_content``. Multipart fields, streaming, retries, and pool options
    fail closed rather than being silently ignored.
    """

    def __init__(self, policy: FetchPolicy | None = None, *, fetcher: SafeFetcher | None = None) -> None:
        if policy is not None and fetcher is not None:
            raise ValueError("Pass either fetcher or policy, not both")
        self.fetcher = fetcher or SafeFetcher(policy)

    def request(self, method: str, url: str, **kwargs: Any) -> HTTPResponse:
        body = kwargs.pop("body", None)
        headers = kwargs.pop("headers", None)
        json_body = kwargs.pop("json", None)
        policy = kwargs.pop("policy", None)
        redirect = kwargs.pop("redirect", True)
        timeout = kwargs.pop("timeout", None)
        preload_content = kwargs.pop("preload_content", True)
        decode_content = kwargs.pop("decode_content", True)

        if kwargs:
            unsupported = ", ".join(sorted(kwargs))
            raise PolicyError(f"Unsupported urllib3 request options: {unsupported}")
        if not isinstance(redirect, bool):
            raise PolicyError("redirect must be a boolean")
        if preload_content is not True:
            raise PolicyError("Streaming urllib3 responses are unsupported")
        if not isinstance(decode_content, bool):
            raise PolicyError("decode_content must be a boolean")
        if policy is not None and not isinstance(policy, FetchPolicy):
            raise PolicyError("policy must be a FetchPolicy")
        active_policy = self.fetcher.policy if policy is None else policy
        if json_body is not None:
            if body is not None:
                raise PolicyError("Pass either body or json, not both")
            body = json_module.dumps(json_body, separators=(",", ":")).encode("utf-8")
            headers = dict(headers or {})
            if not any(name.lower() == "content-type" for name in headers):
                headers["Content-Type"] = "application/json"

        request_body = self._body_bytes(body, active_policy.max_request_bytes)
        timeout_seconds = self._timeout_seconds(timeout)
        try:
            result = self.fetcher.request(
                method,
                url,
                headers=headers,
                body=request_body,
                timeout_seconds=timeout_seconds,
                follow_redirects=redirect,
                policy=policy,
            )
        except FetchError as exc:
            raise SafeUrllib3Error(str(exc)) from exc

        response_headers = HTTPHeaderDict()
        for name, value in result.headers:
            response_headers.add(name, value)
        return HTTPResponse(
            body=BytesIO(result.content),
            headers=response_headers,
            status=result.status_code,
            reason="",
            preload_content=True,
            decode_content=decode_content,
            request_method=result.method,
            request_url=result.url,
        )

    def _body_bytes(self, body: Any, limit: int | None = None) -> bytes | None:
        if body is None:
            return None
        limit = self.fetcher.policy.max_request_bytes if limit is None else limit
        if isinstance(body, bytes):
            result = body
        elif isinstance(body, str):
            result = body.encode("utf-8")
        elif hasattr(body, "read"):
            result = body.read(limit + 1)
            if isinstance(result, str):
                result = result.encode("utf-8")
            if not isinstance(result, bytes):
                raise PolicyError("File-like request body must produce bytes or text")
        else:
            raise PolicyError("Iterable request bodies are unsupported")
        if len(result) > limit:
            raise RequestTooLargeError("Request body exceeded the configured byte limit")
        return result

    @staticmethod
    def _timeout_seconds(timeout: Any) -> float | None:
        if timeout is None:
            return None
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
            raise PolicyError("timeout must be a positive number or None")
        return float(timeout)


# PoolManager-shaped facade kept beside the urllib3 client implementation.
exceptions = urllib3.exceptions


class PoolManager:
    """Small safe facade for common ``urllib3.PoolManager`` call sites."""

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
    "HTTPHeaderDict", "HTTPResponse", "PoolManager", "SafeUrllib3Client", "SafeUrllib3Error",
    "exceptions", "request",
]
