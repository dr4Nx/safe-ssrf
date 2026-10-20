"""HTTPX transports backed by the policy-enforcing pinned-socket client.

This transport is intentionally explicit. It supports HTTP requests with a
bounded buffered body; it does not use HTTPX's proxy, DNS, pooling, or streaming
transport. Each redirect is handled by :class:`SafeFetcher` and checked before
the next socket is opened.
"""

from __future__ import annotations

import asyncio
from typing import Any

try:
    import httpx
except ImportError as exc:  # pragma: no cover - depends on optional extra
    raise ImportError("SafeHTTPXTransport requires the optional 'httpx' dependency") from exc

from .client import SafeFetcher
from .errors import FetchError
from .policy import FetchPolicy


class _BufferedAsyncStream(httpx.AsyncByteStream):
    def __init__(self, content: bytes) -> None:
        self._content = content

    async def __aiter__(self):
        yield self._content

    async def aclose(self) -> None:
        return None


class _OriginalOrigin:
    """Private marker carried through HTTPX's redirect request extensions."""

    def __init__(self, origin: tuple[str, str, int]) -> None:
        self.origin = origin


_ORIGINAL_ORIGIN_EXTENSION = "safe_egress.original_origin"


def _request_headers(request: httpx.Request, fetcher: SafeFetcher) -> dict[str, str]:
    # HTTPX always supplies Host. SafeFetcher derives it from the validated
    # URL and refuses caller-supplied Host headers to prevent routing drift.
    headers = {
        name: value
        for name, value in request.headers.items()
        if name.lower() not in {"host", "content-length", "transfer-encoding"}
    }
    target = fetcher._parse_target(str(request.url))
    state = request.extensions.get(_ORIGINAL_ORIGIN_EXTENSION)
    if not isinstance(state, _OriginalOrigin):
        state = _OriginalOrigin(target.origin)
        request.extensions[_ORIGINAL_ORIGIN_EXTENSION] = state
    if target.origin != state.origin:
        sensitive = {"authorization", "cookie", "origin"}
        headers = {name: value for name, value in headers.items() if name.lower() not in sensitive}
    return headers


def _request_timeout(request: httpx.Request) -> float | None:
    timeout_settings = request.extensions.get("timeout")
    timeout_values = (
        [value for value in timeout_settings.values() if isinstance(value, (int, float))]
        if isinstance(timeout_settings, dict)
        else []
    )
    return min(timeout_values) if timeout_values else None


class SafeHTTPXSyncTransport(httpx.BaseTransport):
    """Synchronous HTTPX transport with destination checks at connect time."""

    def __init__(self, fetcher: SafeFetcher | None = None, *, policy: FetchPolicy | None = None) -> None:
        if fetcher is not None and policy is not None:
            raise ValueError("Pass either fetcher or policy, not both")
        self.fetcher = fetcher or SafeFetcher(policy)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        body = self._read_request_body(request)
        headers = _request_headers(request, self.fetcher)
        try:
            result = self.fetcher.request(
                request.method,
                str(request.url),
                headers=headers,
                body=body,
                timeout_seconds=_request_timeout(request),
                follow_redirects=False,
            )
        except FetchError as exc:
            raise httpx.ConnectError(str(exc), request=request) from exc

        return httpx.Response(
            result.status_code,
            headers=result.headers,
            content=result.content,
            request=request,
        )

    def close(self) -> None:
        return None

    def _read_request_body(self, request: httpx.Request) -> bytes | None:
        chunks: list[bytes] = []
        total = 0
        for chunk in request.stream:
            total += len(chunk)
            if total > self.fetcher.policy.max_request_bytes:
                raise httpx.RequestError("Request body exceeded the configured byte limit", request=request)
            chunks.append(chunk)
        if not chunks:
            return None
        return b"".join(chunks)


class SafeHTTPXTransport(httpx.AsyncBaseTransport):
    """An HTTPX transport that routes requests through ``SafeFetcher``.

    The adapter buffers request and response bodies to enforce configured byte
    limits. It supports all HTTP methods with byte request bodies and standard
    HTTP(S) URLs. It deliberately rejects non-byte/oversized request streams.
    Proxies and HTTPX connection pooling are not used; the fetcher's explicit
    destination policy and pinned TCP connection are authoritative.
    """

    def __init__(self, fetcher: SafeFetcher | None = None, *, policy: FetchPolicy | None = None) -> None:
        if fetcher is not None and policy is not None:
            raise ValueError("Pass either fetcher or policy, not both")
        self.fetcher = fetcher or SafeFetcher(policy)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = await self._read_request_body(request)
        headers = _request_headers(request, self.fetcher)
        try:
            result = await asyncio.to_thread(
                self.fetcher.request,
                request.method,
                str(request.url),
                headers=headers,
                body=body,
                timeout_seconds=_request_timeout(request),
                follow_redirects=False,
            )
        except FetchError as exc:
            raise httpx.ConnectError(str(exc), request=request) from exc

        final_request = httpx.Request(result.method, result.url, headers=headers)
        return httpx.Response(
            result.status_code,
            headers=result.headers,
            stream=_BufferedAsyncStream(result.content),
            request=final_request,
        )

    async def aclose(self) -> None:
        return None

    async def _read_request_body(self, request: httpx.Request) -> bytes | None:
        chunks: list[bytes] = []
        total = 0
        stream = request.stream
        if hasattr(stream, "__aiter__"):
            async for chunk in stream:
                total += len(chunk)
                if total > self.fetcher.policy.max_request_bytes:
                    raise httpx.RequestError("Request body exceeded the configured byte limit", request=request)
                chunks.append(chunk)
        else:
            for chunk in stream:
                total += len(chunk)
                if total > self.fetcher.policy.max_request_bytes:
                    raise httpx.RequestError("Request body exceeded the configured byte limit", request=request)
                chunks.append(chunk)
        if not chunks:
            return None
        return b"".join(chunks)


class SafeAsyncClient(httpx.AsyncClient):
    """HTTPX AsyncClient with the safe transport installed and proxy paths off.

    Use this client rather than installing ``SafeHTTPXTransport`` into a
    general-purpose client with proxy mounts. HTTPX proxy and custom transport
    options are rejected because they could route around the pinned direct
    connection policy. ``trust_env`` is forced off so environment proxy
    variables cannot select another transport.
    """

    def __init__(
        self,
        *,
        fetcher: SafeFetcher | None = None,
        policy: FetchPolicy | None = None,
        **kwargs: Any,
    ) -> None:
        forbidden = {
            key
            for key, value in kwargs.items()
            if key == "transport"
            or (key in {"proxy", "proxies"} and value is not None)
            or (key == "mounts" and bool(value))
        }
        if forbidden:
            options = ", ".join(sorted(forbidden))
            raise ValueError(f"SafeAsyncClient does not support HTTPX options that can replace routing: {options}")
        kwargs.pop("proxy", None)
        kwargs.pop("proxies", None)
        kwargs.pop("mounts", None)
        if kwargs.pop("trust_env", False):
            raise ValueError("SafeAsyncClient disables trust_env; configure an explicit supported policy instead")
        if kwargs.get("verify", True) is not True:
            raise ValueError("Custom or disabled TLS verification is unsupported by SafeAsyncClient")
        kwargs.pop("verify", None)
        if fetcher is not None and policy is not None:
            raise ValueError("Pass either fetcher or policy, not both")
        fetcher = fetcher or SafeFetcher(policy)
        requested_redirect_limit = kwargs.get("max_redirects", 20)
        kwargs["max_redirects"] = min(requested_redirect_limit, fetcher.policy.max_redirects)
        super().__init__(transport=SafeHTTPXTransport(fetcher), trust_env=False, **kwargs)


class SafeClient(httpx.Client):
    """Synchronous HTTPX client with destination policy and pinned sockets."""

    def __init__(
        self,
        *,
        fetcher: SafeFetcher | None = None,
        policy: FetchPolicy | None = None,
        **kwargs: Any,
    ) -> None:
        forbidden = {
            key
            for key, value in kwargs.items()
            if key == "transport"
            or (key in {"proxy", "proxies"} and value is not None)
            or (key == "mounts" and bool(value))
        }
        if forbidden:
            options = ", ".join(sorted(forbidden))
            raise ValueError(f"SafeClient does not support HTTPX options that can replace routing: {options}")
        kwargs.pop("proxy", None)
        kwargs.pop("proxies", None)
        kwargs.pop("mounts", None)
        if kwargs.pop("trust_env", False):
            raise ValueError("SafeClient disables trust_env; configure an explicit supported policy instead")
        if kwargs.get("verify", True) is not True:
            raise ValueError("Custom or disabled TLS verification is unsupported by SafeClient")
        kwargs.pop("verify", None)
        if fetcher is not None and policy is not None:
            raise ValueError("Pass either fetcher or policy, not both")
        fetcher = fetcher or SafeFetcher(policy)
        requested_redirect_limit = kwargs.get("max_redirects", 20)
        kwargs["max_redirects"] = min(requested_redirect_limit, fetcher.policy.max_redirects)
        super().__init__(transport=SafeHTTPXSyncTransport(fetcher), trust_env=False, **kwargs)
