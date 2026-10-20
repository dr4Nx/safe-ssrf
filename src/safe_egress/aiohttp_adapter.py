"""aiohttp session with destination checks in its DNS resolver.

The resolver validates every DNS result before aiohttp can open a socket. The
connector then connects to one of those numeric addresses, avoiding a second
hostname lookup. Redirects resolve again through the same policy resolver.
Cross-origin redirects remove authorization, cookie, and origin headers.
Cookie storage, URL credentials, proxy routes, and caller-supplied connectors
are rejected because they can weaken destination or credential boundaries.

This adapter uses aiohttp's resolver and request-class extension points.
Review this integration when upgrading aiohttp; it is not a drop-in
replacement for every aiohttp extension or session customization.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any

try:
    import aiohttp
    from yarl import URL
except ImportError as exc:  # pragma: no cover - depends on optional extra
    raise ImportError("safe_aiohttp_session requires the optional 'aiohttp' dependency") from exc

from .errors import PolicyError, RedirectLimitError, ResponseTooLargeError
from .policy import FetchPolicy


class _PolicyResolver(aiohttp.abc.AbstractResolver):
    """Resolve names only when every possible address satisfies the policy."""

    def __init__(self, policy: FetchPolicy) -> None:
        self._policy = policy

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: int = socket.AF_INET,
    ) -> list[dict[str, Any]]:
        normalized = self._policy.check_host(host)
        self._policy.check_port(port)
        try:
            literal = ipaddress.ip_address(normalized)
        except ValueError:
            literal = None

        if literal is not None:
            addresses: list[tuple[int, str]] = [
                (socket.AF_INET6 if literal.version == 6 else socket.AF_INET, literal.compressed)
            ]
        else:
            loop = asyncio.get_running_loop()
            try:
                records = await loop.getaddrinfo(
                    normalized,
                    port,
                    family=family,
                    type=socket.SOCK_STREAM,
                )
            except OSError as exc:
                raise PolicyError("Hostname resolution failed") from exc
            addresses = []
            for record in records:
                try:
                    address_text = record[4][0]
                    if "%" in address_text:
                        raise ValueError("Scoped IPv6 address")
                    parsed = ipaddress.ip_address(address_text)
                    addresses.append(
                        (socket.AF_INET6 if parsed.version == 6 else socket.AF_INET, parsed.compressed)
                    )
                except (IndexError, ValueError) as exc:
                    raise PolicyError("Resolver returned an unsupported address") from exc

        # Check every result, including mixed public/private answers, before
        # returning any address to aiohttp's connector.
        unique_addresses = list(dict.fromkeys(addresses))
        if not unique_addresses:
            raise PolicyError("Hostname resolved to no usable addresses")
        private_override = self._policy.permits_private(normalized)
        if not private_override:
            for _, address_text in unique_addresses:
                address = ipaddress.ip_address(address_text)
                if not self._policy.is_public_address(address):
                    raise PolicyError("Hostname resolved to a non-public address")

        return [
            {
                "hostname": normalized,
                "host": address,
                "port": port,
                "family": address_family,
                "proto": socket.IPPROTO_TCP,
                "flags": socket.AI_NUMERICHOST,
            }
            for address_family, address in unique_addresses
        ]

    async def close(self) -> None:
        return None


class _BoundedStreamReader:
    """Delegate aiohttp stream reads while enforcing a decoded-byte limit."""

    def __init__(self, reader: Any, limit: int, close_response: Any) -> None:
        self._reader = reader
        self._limit = limit
        self._close_response = close_response
        self._read_bytes = 0

    def _record(self, data: bytes) -> bytes:
        self._read_bytes += len(data)
        if self._read_bytes > self._limit:
            self._close_response()
            raise ResponseTooLargeError("Response body exceeded the configured byte limit")
        return data

    async def read(self, n: int = -1) -> bytes:
        remaining = self._limit - self._read_bytes
        read_size = remaining + 1 if n < 0 else min(n, remaining + 1)
        return self._record(await self._reader.read(read_size))

    async def readany(self) -> bytes:
        return self._record(await self._reader.readany())

    async def readline(self) -> bytes:
        return self._record(await self._reader.readline())

    async def readuntil(self, separator: bytes = b"\n") -> bytes:
        return self._record(await self._reader.readuntil(separator))

    async def readexactly(self, n: int) -> bytes:
        remaining = self._limit - self._read_bytes
        read_size = min(n, remaining + 1)
        try:
            data = await self._reader.readexactly(read_size)
        except asyncio.IncompleteReadError as exc:
            self._record(exc.partial)
            raise
        return self._record(data)

    def read_nowait(self, n: int = -1) -> bytes:
        remaining = self._limit - self._read_bytes
        read_size = remaining + 1 if n < 0 else min(n, remaining + 1)
        return self._record(self._reader.read_nowait(read_size))

    async def readchunk(self) -> tuple[bytes, bool]:
        data, end_of_http_chunk = await self._reader.readchunk()
        return self._record(data), end_of_http_chunk

    def iter_chunked(self, n: int):
        async def chunks():
            while True:
                chunk = await self.read(n)
                if not chunk:
                    break
                yield chunk

        return chunks()

    def iter_any(self):
        async def chunks():
            while True:
                chunk = await self.readany()
                if not chunk:
                    break
                yield chunk

        return chunks()

    def iter_chunks(self):
        async def chunks():
            async for data, end_of_http_chunk in self._reader.iter_chunks():
                yield self._record(data), end_of_http_chunk

        return chunks()

    def __aiter__(self):
        return self

    async def __anext__(self) -> bytes:
        line = await self.readline()
        if not line:
            raise StopAsyncIteration
        return line

    def __getattr__(self, name: str) -> Any:
        return getattr(self._reader, name)


def _response_class_for(limit: int) -> type[aiohttp.ClientResponse]:
    """Wrap every response body reader with the policy's decoded-byte cap."""

    class _PolicyClientResponse(aiohttp.ClientResponse):
        async def start(self, connection: Any) -> aiohttp.ClientResponse:
            await super().start(connection)
            self.content = _BoundedStreamReader(self.content, limit, self.close)
            return self

    _PolicyClientResponse.__name__ = "PolicyClientResponse"
    return _PolicyClientResponse


def _request_class_for(policy: FetchPolicy) -> type[aiohttp.ClientRequest]:
    """Build the aiohttp request class with URL and proxy checks.

    aiohttp's connector skips custom resolvers for IP literals, so validate
    those destinations here before its connector can open the socket.
    """

    class _PolicyClientRequest(aiohttp.ClientRequest):
        def __init__(self, method: str, url: Any, **kwargs: Any) -> None:
            proxy_headers = kwargs.get("proxy_headers")
            if (
                kwargs.get("proxy") is not None
                or kwargs.get("proxy_auth") is not None
                or bool(proxy_headers)
            ):
                raise ValueError("Safe aiohttp requests do not allow proxies")
            if kwargs.get("ssl", True) not in (None, True):
                raise ValueError("Custom or disabled TLS verification is unsupported")

            headers = kwargs.get("headers") or {}
            if any(name.lower() == "host" for name in headers):
                # Keep the HTTP authority aligned with the URL that was
                # checked by this request class and resolved by the policy
                # connector. A caller-supplied Host can route a public IP to
                # an unintended virtual host.
                raise PolicyError("Host headers are managed by the safe aiohttp session")
            if kwargs.get("cookies"):
                raise PolicyError("Per-request cookies are unsupported by the safe aiohttp session")
            if url.user is not None or url.password is not None or url.fragment:
                raise PolicyError("URL credentials and fragments are not accepted")

            scheme = url.scheme.lower()
            if scheme not in {"http", "https"}:
                raise PolicyError("Only HTTP and HTTPS URLs are supported")
            host = policy.check_host(url.host)
            port = url.port
            if port is None:
                port = 443 if scheme == "https" else 80
            policy.check_port(port)
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                address = None
            if address is not None and not policy.permits_private(host) and not policy.is_public_address(address):
                raise PolicyError("IP literal is not a public address")

            super().__init__(method, url, **kwargs)

    _PolicyClientRequest.__name__ = "PolicyClientRequest"
    return _PolicyClientRequest


async def _strip_cross_origin_redirect_headers(
    _session: aiohttp.ClientSession,
    _context: Any,
    params: Any,
) -> None:
    """Remove caller credentials before aiohttp sends a cross-origin hop."""
    location = params.response.headers.get("Location") or params.response.headers.get("URI")
    if location is None:
        return
    try:
        next_url = params.url.join(URL(location))
        cross_origin = params.url.origin() != next_url.origin()
    except ValueError:
        # aiohttp will reject malformed redirect destinations itself; no
        # redirected request should be sent with the original headers.
        cross_origin = True
    if cross_origin:
        for name in ("Authorization", "Cookie", "Origin"):
            params.headers.pop(name, None)


def _safe_redirect_trace_config(policy: FetchPolicy) -> aiohttp.TraceConfig:
    """Apply the redirect cap and credential policy to each aiohttp request."""
    trace = aiohttp.TraceConfig()

    async def handle_redirect(session: aiohttp.ClientSession, context: Any, params: Any) -> None:
        count = getattr(context, "safe_egress_redirect_count", 0) + 1
        context.safe_egress_redirect_count = count
        if count > policy.max_redirects:
            raise RedirectLimitError("The response exceeded the configured redirect limit")
        await _strip_cross_origin_redirect_headers(session, context, params)

    trace.on_request_redirect.append(handle_redirect)
    return trace


def safe_aiohttp_session(
    *,
    policy: FetchPolicy | None = None,
    **kwargs: Any,
) -> aiohttp.ClientSession:
    """Create a standard aiohttp session with destination policy enabled.

    The default policy allows only globally routable resolved addresses over
    ports 80 and 443. Supply a ``FetchPolicy`` to customize exact host/port
    rules. Response reads and iterators are capped at ``max_response_bytes``.
    Do not pass proxies, cookie jars, connectors, request/response classes,
    middleware, session-wide ``auth``, or ``trust_env=True``. Per-request
    cookies and URL credentials are rejected.

    aiohttp's public request-class extension point rejects per-request proxies.
    Using a standard ``ClientSession`` avoids relying on its private request
    method and avoids subclassing the session class.
    """
    if kwargs.get("connector") is not None:
        raise ValueError("A safe aiohttp session does not accept a custom connector")
    if kwargs.get("trust_env", False):
        raise ValueError("A safe aiohttp session disables trust_env")
    if kwargs.get("proxy") is not None:
        raise ValueError("A safe aiohttp session does not accept a session proxy")
    if kwargs.get("auth") is not None:
        # aiohttp reapplies ClientSession._default_auth at the top of each
        # redirect iteration, including after its cross-origin branch clears
        # the current auth value. The trace hook can remove headers but cannot
        # prevent this constructor-level auth from being generated again.
        raise ValueError("A safe aiohttp session does not accept session-wide auth")
    if kwargs.get("middlewares"):
        raise ValueError("A safe aiohttp session does not accept custom middleware")
    if kwargs.get("request_class", aiohttp.ClientRequest) is not aiohttp.ClientRequest:
        raise ValueError("A safe aiohttp session does not accept a custom request class")
    if kwargs.get("response_class", aiohttp.ClientResponse) is not aiohttp.ClientResponse:
        raise ValueError("A safe aiohttp session does not accept a custom response class")
    if kwargs.get("cookie_jar") is not None:
        raise ValueError("A safe aiohttp session does not accept a cookie jar")

    selected_policy = policy or FetchPolicy()
    connector = aiohttp.TCPConnector(resolver=_PolicyResolver(selected_policy), use_dns_cache=False)
    trace_configs = list(kwargs.pop("trace_configs", None) or ())
    trace_configs.append(_safe_redirect_trace_config(selected_policy))
    kwargs.pop("trust_env", None)
    kwargs.pop("proxy", None)
    kwargs.pop("middlewares", None)
    kwargs["cookie_jar"] = aiohttp.DummyCookieJar()
    kwargs["trace_configs"] = trace_configs
    kwargs["request_class"] = _request_class_for(selected_policy)
    kwargs["response_class"] = _response_class_for(selected_policy.max_response_bytes)
    return aiohttp.ClientSession(connector=connector, trust_env=False, **kwargs)
