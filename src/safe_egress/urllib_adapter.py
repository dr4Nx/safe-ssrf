"""A small ``urllib.request.urlopen``-style facade backed by SafeFetcher.

This is not a process-wide patch or a full ``OpenerDirector`` replacement. It
supports HTTP(S) Requests, bounded byte/text/file request bodies, headers,
numeric timeouts, checked redirects, and buffered response reads. Cookie,
proxy-handler, custom TLS-context, streaming, and non-HTTP handler behavior is
not implemented.
"""

from __future__ import annotations

from email.message import Message
from io import BytesIO
import math
from typing import Any
import urllib.error
import urllib.request

from .client import SafeFetcher
from .errors import FetchError, PolicyError, RequestTooLargeError
from .policy import FetchPolicy


class SafeUrllibError(urllib.error.URLError):
    """A ``urllib``-compatible error for safe-fetch policy/transport failures."""


class SafeUrllibOpener:
    """Fetch URLs using a narrow ``urlopen``-compatible API.

    Example::

        with SafeUrllibOpener().open(user_url, timeout=5) as response:
            body = response.read()

    HTTP error statuses raise ``urllib.error.HTTPError``, as with
    ``urllib.request.urlopen``. All responses are bounded and buffered before
    they are returned.
    """

    def __init__(self, policy: FetchPolicy | None = None, *, fetcher: SafeFetcher | None = None) -> None:
        if policy is not None and fetcher is not None:
            raise ValueError("Pass either fetcher or policy, not both")
        self.fetcher = fetcher or SafeFetcher(policy)

    def open(
        self,
        fullurl: str | urllib.request.Request,
        data: bytes | str | None = None,
        timeout: float | None = None,
        **kwargs: Any,
    ):
        """Open an HTTP(S) URL or prepared ``urllib.request.Request`` safely."""
        context = kwargs.pop("context", None)
        policy = kwargs.pop("policy", None)
        if context is not None:
            raise PolicyError("Custom TLS contexts are unsupported by SafeUrllibOpener")
        if kwargs:
            unsupported = ", ".join(sorted(kwargs))
            raise PolicyError(f"Unsupported urllib.request options: {unsupported}")
        if policy is not None and not isinstance(policy, FetchPolicy):
            raise PolicyError("policy must be a FetchPolicy")
        active_policy = self.fetcher.policy if policy is None else policy

        if isinstance(fullurl, urllib.request.Request):
            request = fullurl
            if data is not None:
                raise PolicyError("Pass request data on the Request object or to open(), not both")
        else:
            request = urllib.request.Request(fullurl, data=data)

        body = self._body_bytes(request.data, active_policy.max_request_bytes)
        timeout_seconds = self._timeout_seconds(timeout)
        headers = dict(request.header_items())
        try:
            fetched = self.fetcher.request(
                request.get_method(),
                request.full_url,
                headers=headers,
                body=body,
                timeout_seconds=timeout_seconds,
                policy=policy,
            )
        except FetchError as exc:
            raise SafeUrllibError(str(exc)) from exc

        response_headers = Message()
        for name, value in fetched.headers:
            response_headers.add_header(name, value)
        response = urllib.response.addinfourl(
            BytesIO(fetched.content),
            response_headers,
            fetched.url,
            code=fetched.status_code,
        )
        if fetched.status_code >= 400:
            raise urllib.error.HTTPError(
                fetched.url,
                fetched.status_code,
                f"HTTP Error {fetched.status_code}",
                response_headers,
                response,
            )
        return response

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
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise PolicyError("timeout must be a positive finite number or None")
        return float(timeout)
