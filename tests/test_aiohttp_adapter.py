from __future__ import annotations

import asyncio
import socket
import unittest
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

try:
    import aiohttp
except ImportError:  # pragma: no cover - optional test dependency
    aiohttp = None

from safe_egress import FetchPolicy, PolicyError, RedirectLimitError, ResponseTooLargeError


class _FixtureTransport:
    """Tiny asyncio transport that returns one canned HTTP response in memory."""

    def __init__(self, loop: asyncio.AbstractEventLoop, protocol: Any, response: bytes) -> None:
        self._loop = loop
        self._protocol = protocol
        self._response = response
        self._sent_response = False
        self._closed = False
        self.writes: list[bytes] = []

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        return default

    def is_closing(self) -> bool:
        return self._closed

    def write(self, data: bytes) -> None:
        self.writes.append(data)
        if not self._sent_response:
            self._sent_response = True
            self._loop.call_soon(self._protocol.data_received, self._response)

    def writelines(self, data: list[bytes]) -> None:
        self.write(b"".join(data))

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._protocol.connection_lost(None)

    def abort(self) -> None:
        self.close()

    def can_write_eof(self) -> bool:
        return True

    def write_eof(self) -> None:
        self.close()

    def set_write_buffer_limits(self, *args: Any, **kwargs: Any) -> None:
        return None

    def get_write_buffer_size(self) -> int:
        return 0

    def get_write_buffer_limits(self) -> tuple[int, int]:
        return (0, 0)


@unittest.skipIf(aiohttp is None, "install safe-egress[aiohttp] to run aiohttp adapter tests")
class SafeAiohttpResolverTests(unittest.IsolatedAsyncioTestCase):
    async def test_public_destination_is_returned_as_numeric_address(self) -> None:
        from safe_egress.aiohttp_adapter import _PolicyResolver

        loop = asyncio.get_running_loop()
        records = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 80))]
        with patch.object(loop, "getaddrinfo", new=AsyncMock(return_value=records)):
            result = await _PolicyResolver(FetchPolicy()).resolve("public.example", 80, socket.AF_UNSPEC)

        self.assertEqual([entry["host"] for entry in result], ["93.184.216.34"])
        self.assertEqual(result[0]["flags"], socket.AI_NUMERICHOST)

    async def test_mixed_public_and_loopback_dns_results_are_rejected(self) -> None:
        from safe_egress.aiohttp_adapter import _PolicyResolver

        loop = asyncio.get_running_loop()
        records = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 80)),
        ]
        with patch.object(loop, "getaddrinfo", new=AsyncMock(return_value=records)):
            with self.assertRaises(PolicyError):
                await _PolicyResolver(FetchPolicy()).resolve("mixed.example", 80, socket.AF_UNSPEC)

    async def test_loopback_literal_is_rejected_without_dns(self) -> None:
        from safe_egress.aiohttp_adapter import _PolicyResolver

        with self.assertRaises(PolicyError):
            await _PolicyResolver(FetchPolicy()).resolve("127.0.0.1", 80, socket.AF_UNSPEC)

    async def test_exact_private_exception_is_supported(self) -> None:
        from safe_egress.aiohttp_adapter import _PolicyResolver

        policy = FetchPolicy(allowed_hosts=frozenset({"internal.test"}), allowed_private_hosts=frozenset({"internal.test"}))
        loop = asyncio.get_running_loop()
        records = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 80))]
        with patch.object(loop, "getaddrinfo", new=AsyncMock(return_value=records)):
            result = await _PolicyResolver(policy).resolve("internal.test", 80, socket.AF_UNSPEC)

        self.assertEqual([entry["host"] for entry in result], ["127.0.0.1"])

    async def test_rejects_disallowed_ports_and_proxy_options(self) -> None:
        from safe_egress.aiohttp_adapter import _PolicyResolver, safe_aiohttp_session

        with self.assertRaises(PolicyError):
            await _PolicyResolver(FetchPolicy()).resolve("93.184.216.34", 8080, socket.AF_UNSPEC)

        async with safe_aiohttp_session() as session:
            with self.assertRaises(ValueError):
                await session.get("http://example.com/", proxy="http://proxy.example")

    async def test_session_rejects_custom_routing_configuration(self) -> None:
        from safe_egress.aiohttp_adapter import safe_aiohttp_session

        class CustomResponse(aiohttp.ClientResponse):
            pass

        for options in (
            {"connector": aiohttp.TCPConnector()},
            {"trust_env": True},
            {"auth": aiohttp.BasicAuth("dummy-user", "dummy-password")},
            {"middlewares": (lambda *args: None,)},
            {"response_class": CustomResponse},
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                safe_aiohttp_session(**options)

    async def test_session_blocks_loopback_before_connector_attempt(self) -> None:
        from safe_egress.aiohttp_adapter import safe_aiohttp_session

        connector_attempt = AsyncMock()
        with patch.object(aiohttp.TCPConnector, "_create_connection", new=connector_attempt):
            async with safe_aiohttp_session() as session:
                with self.assertRaises(PolicyError):
                    await session.get("http://127.0.0.1/internal-status")

        connector_attempt.assert_not_awaited()

    async def test_session_rejects_caller_host_header(self) -> None:
        from safe_egress.aiohttp_adapter import safe_aiohttp_session

        connector_attempt = AsyncMock()
        with patch.object(aiohttp.TCPConnector, "_create_connection", new=connector_attempt):
            async with safe_aiohttp_session() as session:
                with self.assertRaises(PolicyError):
                    await session.get(
                        "http://example.com/resource",
                        headers={"Host": "internal-admin.example"},
                    )

        connector_attempt.assert_not_awaited()

    async def test_session_rejects_url_credentials_and_per_request_cookies(self) -> None:
        from safe_egress.aiohttp_adapter import safe_aiohttp_session

        async with safe_aiohttp_session() as session:
            with self.assertRaises(PolicyError):
                await session.get("http://user:dummy@example.com/resource")
            with self.assertRaises(PolicyError):
                await session.get("http://example.com/resource", cookies={"session": "dummy"})

        with self.assertRaises(ValueError):
            safe_aiohttp_session(cookie_jar=aiohttp.CookieJar())

    async def test_cross_origin_redirect_trace_strips_sensitive_headers(self) -> None:
        from multidict import CIMultiDict
        from yarl import URL

        from safe_egress.aiohttp_adapter import _strip_cross_origin_redirect_headers

        headers = CIMultiDict(
            {
                "Authorization": "Bearer dummy",
                "Cookie": "session=dummy",
                "Origin": "https://caller.example",
                "X-Public": "preserved",
            }
        )
        params = SimpleNamespace(
            url=URL("https://public.example/start"),
            response=SimpleNamespace(headers={"Location": "https://other.example/next"}),
            headers=headers,
        )
        await _strip_cross_origin_redirect_headers(None, None, params)

        self.assertNotIn("Authorization", headers)
        self.assertNotIn("Cookie", headers)
        self.assertNotIn("Origin", headers)
        self.assertEqual(headers["X-Public"], "preserved")

    async def test_session_enforces_policy_redirect_hop_limit(self) -> None:
        from safe_egress.aiohttp_adapter import safe_aiohttp_session

        loop = asyncio.get_running_loop()
        records = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 80))]
        resolver_call = AsyncMock(return_value=records)
        wire_responses = [
            b"HTTP/1.1 302 Found\r\nLocation: /one\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 302 Found\r\nLocation: /two\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ]
        transports: list[_FixtureTransport] = []

        async def in_memory_connection(connector, factory, *args, **kwargs):
            del connector, args, kwargs
            protocol = factory()
            response = wire_responses[len(transports)]
            transport = _FixtureTransport(loop, protocol, response)
            transports.append(transport)
            protocol.connection_made(transport)
            return transport, protocol

        with patch.object(loop, "getaddrinfo", new=resolver_call), patch.object(
            aiohttp.TCPConnector, "_wrap_create_connection", new=in_memory_connection
        ):
            async with safe_aiohttp_session(policy=FetchPolicy(max_redirects=1)) as session:
                with self.assertRaises(RedirectLimitError):
                    await session.get("http://public.example/start")

        self.assertEqual(len(transports), 2)
        self.assertEqual(resolver_call.await_count, 2)
        requests = [b"".join(transport.writes) for transport in transports]
        self.assertIn(b"GET /start HTTP/1.1", requests[0])
        self.assertIn(b"GET /one HTTP/1.1", requests[1])

    async def test_session_allows_public_request_through_policy_resolver(self) -> None:
        from safe_egress.aiohttp_adapter import safe_aiohttp_session

        loop = asyncio.get_running_loop()
        records = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 80))]
        resolver_call = AsyncMock(return_value=records)
        socket_attempt = AsyncMock(side_effect=RuntimeError("stop before socket creation"))
        with patch.object(loop, "getaddrinfo", new=resolver_call), patch.object(
            aiohttp.TCPConnector, "_wrap_create_connection", new=socket_attempt
        ):
            async with safe_aiohttp_session() as session:
                with self.assertRaisesRegex(RuntimeError, "stop before socket creation"):
                    await session.get("http://public.example/resource")

        resolver_call.assert_awaited_once()
        socket_attempt.assert_awaited_once()

    async def test_session_fetches_public_fixture_without_opening_socket(self) -> None:
        from safe_egress.aiohttp_adapter import safe_aiohttp_session

        loop = asyncio.get_running_loop()
        records = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 80))]
        resolver_call = AsyncMock(return_value=records)
        transports: list[_FixtureTransport] = []
        body = b"PUBLIC_FIXTURE_CONTENT"
        wire_response = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
            + str(len(body)).encode("ascii")
            + b"\r\nConnection: close\r\n\r\n"
            + body
        )

        async def in_memory_connection(connector, factory, *args, **kwargs):
            protocol = factory()
            transport = _FixtureTransport(loop, protocol, wire_response)
            transports.append(transport)
            protocol.connection_made(transport)
            return transport, protocol

        with patch.object(loop, "getaddrinfo", new=resolver_call), patch.object(
            aiohttp.TCPConnector, "_wrap_create_connection", new=in_memory_connection
        ):
            async with safe_aiohttp_session(
                policy=FetchPolicy(max_response_bytes=len(body))
            ) as session:
                async with session.get("http://public.example/resource") as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(await response.text(), "PUBLIC_FIXTURE_CONTENT")
                    self.assertEqual(str(response.url), "http://public.example/resource")

        resolver_call.assert_awaited_once()
        self.assertEqual(len(transports), 1)
        request_bytes = b"".join(transports[0].writes)
        self.assertIn(b"GET /resource HTTP/1.1", request_bytes)
        self.assertIn(b"Host: public.example", request_bytes)

    async def test_session_caps_buffered_and_streamed_response_reads(self) -> None:
        from safe_egress.aiohttp_adapter import safe_aiohttp_session

        loop = asyncio.get_running_loop()
        records = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 80))]
        body = b"PUBLIC_FIXTURE_TOO_LARGE"
        wire_response = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
            + str(len(body)).encode("ascii")
            + b"\r\nConnection: close\r\n\r\n"
            + body
        )
        resolver_call = AsyncMock(return_value=records)
        transports: list[_FixtureTransport] = []

        async def in_memory_connection(connector, factory, *args, **kwargs):
            del connector, args, kwargs
            protocol = factory()
            transport = _FixtureTransport(loop, protocol, wire_response)
            transports.append(transport)
            protocol.connection_made(transport)
            return transport, protocol

        with patch.object(loop, "getaddrinfo", new=resolver_call), patch.object(
            aiohttp.TCPConnector, "_wrap_create_connection", new=in_memory_connection
        ):
            async with safe_aiohttp_session(policy=FetchPolicy(max_response_bytes=8)) as session:
                async with session.get("http://public.example/buffered") as response:
                    with self.assertRaises(ResponseTooLargeError):
                        await response.read()
                async with session.get("http://public.example/streamed") as response:
                    with self.assertRaises(ResponseTooLargeError):
                        async for _chunk in response.content.iter_chunked(3):
                            pass

        self.assertEqual(len(transports), 2)
        self.assertTrue(all(transport.is_closing() for transport in transports))

    async def test_session_rechecks_redirect_and_strips_cross_origin_headers(self) -> None:
        from safe_egress.aiohttp_adapter import safe_aiohttp_session

        loop = asyncio.get_running_loop()
        records = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 80))]
        first_response = b"HTTP/1.1 302 Found\r\nLocation: http://other.example/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        body = b"PUBLIC_FIXTURE_CONTENT"
        final_response = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
            + str(len(body)).encode("ascii")
            + b"\r\nConnection: close\r\n\r\n"
            + body
        )
        wire_responses = [first_response, final_response]
        resolver_call = AsyncMock(return_value=records)
        transports: list[_FixtureTransport] = []

        async def in_memory_connection(connector, factory, *args, **kwargs):
            protocol = factory()
            transport = _FixtureTransport(loop, protocol, wire_responses[len(transports)])
            transports.append(transport)
            protocol.connection_made(transport)
            return transport, protocol

        with patch.object(loop, "getaddrinfo", new=resolver_call), patch.object(
            aiohttp.TCPConnector, "_wrap_create_connection", new=in_memory_connection
        ):
            async with safe_aiohttp_session() as session:
                async with session.get(
                    "http://public.example/start",
                    headers={
                        "Authorization": "Bearer dummy",
                        "Cookie": "session=dummy",
                        "Origin": "https://caller.example",
                    },
                ) as response:
                    self.assertEqual(await response.text(), "PUBLIC_FIXTURE_CONTENT")

        resolver_call.assert_awaited()
        self.assertEqual(len(transports), 2)
        first_request = b"".join(transports[0].writes).lower()
        second_request = b"".join(transports[1].writes).lower()
        for header in (b"authorization:", b"cookie:", b"origin:"):
            self.assertIn(header, first_request)
            self.assertNotIn(header, second_request)

    async def test_session_blocks_public_to_loopback_redirect_before_second_connection(self) -> None:
        from safe_egress.aiohttp_adapter import safe_aiohttp_session

        loop = asyncio.get_running_loop()
        records = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 80))]
        redirect_response = b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/internal-status\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        resolver_call = AsyncMock(return_value=records)
        transports: list[_FixtureTransport] = []

        async def in_memory_connection(connector, factory, *args, **kwargs):
            protocol = factory()
            transport = _FixtureTransport(loop, protocol, redirect_response)
            transports.append(transport)
            protocol.connection_made(transport)
            return transport, protocol

        with patch.object(loop, "getaddrinfo", new=resolver_call), patch.object(
            aiohttp.TCPConnector, "_wrap_create_connection", new=in_memory_connection
        ):
            async with safe_aiohttp_session() as session:
                with self.assertRaises(PolicyError):
                    await session.get("http://public.example/start")

        resolver_call.assert_awaited_once()
        self.assertEqual(len(transports), 1)

    async def test_ip_literal_policy_is_checked_before_aiohttp_connector(self) -> None:
        from yarl import URL

        from safe_egress.aiohttp_adapter import safe_aiohttp_session

        async with safe_aiohttp_session(policy=FetchPolicy(allowed_ports=frozenset({8080}))) as session:
            request_class = session._request_class
            with self.assertRaises(PolicyError):
                request_class("GET", URL("http://127.0.0.1:8080/internal-status"), session=session)

    async def test_explicit_zero_port_is_not_treated_as_default_http_port(self) -> None:
        from yarl import URL

        from safe_egress.aiohttp_adapter import safe_aiohttp_session

        async with safe_aiohttp_session() as session:
            with self.assertRaises(PolicyError):
                session._request_class("GET", URL("http://127.0.0.1:0/"), session=session)

    async def test_explicit_private_fixture_url_can_be_prepared(self) -> None:
        from yarl import URL

        from safe_egress.aiohttp_adapter import safe_aiohttp_session

        policy = FetchPolicy(
            allowed_hosts=frozenset({"127.0.0.1"}),
            allowed_private_hosts=frozenset({"127.0.0.1"}),
            allowed_ports=frozenset({8080}),
        )
        async with safe_aiohttp_session(policy=policy) as session:
            request = session._request_class("GET", URL("http://127.0.0.1:8080/fixture"), session=session)
            self.assertEqual(request.url.path, "/fixture")
