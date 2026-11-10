from __future__ import annotations

import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import threading
import unittest
import urllib.error
from unittest.mock import patch

try:
    import aiohttp
    import httpx
    import requests
    import urllib3
except ImportError as exc:  # pragma: no cover - depends on optional test extras
    raise unittest.SkipTest(f"optional HTTP client dependency is unavailable: {exc}") from exc

from safe_egress import FetchPolicy, PolicyError
from safe_egress.adapters.aiohttp import safe_aiohttp_session
from safe_egress.adapters.httpx import SafeAsyncClient, SafeClient
from safe_egress.adapters.requests import SafeRequestsSession
from safe_egress.adapters.urllib3 import SafeUrllib3Client
from safe_egress.adapters.urllib import SafeUrllibOpener


_BODY = b"SAFE_EGRESS_LOCAL_FIXTURE"


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.server.requests_seen.append((self.path, self.headers.get("Host")))  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Length", str(len(_BODY)))
        self.end_headers()
        self.wfile.write(_BODY)

    def log_message(self, _format: str, *_args: object) -> None:
        return None


class AdapterSocketDenialTests(unittest.TestCase):
    """Assert each client rejects loopback before invoking socket connect."""

    def test_default_policy_denies_loopback_before_any_client_reaches_fixture(self) -> None:
        url = "http://127.0.0.1/dummy-resource"
        clients = (
            ("Requests", requests.RequestException, lambda: SafeRequestsSession().get(url, timeout=1)),
            ("HTTPX sync", httpx.RequestError, lambda: SafeClient().get(url, timeout=1)),
            ("HTTPX async", httpx.RequestError, lambda: asyncio.run(self._httpx_async_get(url))),
            ("aiohttp", (aiohttp.ClientError, PolicyError), lambda: asyncio.run(self._aiohttp_get(url))),
            ("urllib", urllib.error.URLError, lambda: SafeUrllibOpener().open(url, timeout=1)),
            ("urllib3", urllib3.exceptions.HTTPError, lambda: SafeUrllib3Client().request("GET", url, timeout=1)),
        )
        with patch("socket.socket.connect", side_effect=AssertionError("unexpected socket connect")) as connect, patch(
            "socket.socket.connect_ex", side_effect=AssertionError("unexpected socket connect_ex")
        ) as connect_ex:
            for name, expected_error, request in clients:
                with self.subTest(client=name):
                    with self.assertRaises(expected_error):
                        request()
            connect.assert_not_called()
            connect_ex.assert_not_called()

    async def _httpx_async_get(self, url: str) -> None:
        async with SafeAsyncClient() as client:
            await client.get(url, timeout=1)

    async def _aiohttp_get(self, url: str) -> None:
        async with safe_aiohttp_session() as session:
            async with session.get(url, timeout=1):
                self.fail("aiohttp returned a response for a denied loopback target")


class AdapterSocketUtilityTests(unittest.TestCase):
    """Keep explicit private-service allowances useful for local integrations."""

    @classmethod
    def setUpClass(cls) -> None:
        try:
            cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        except PermissionError as exc:
            raise unittest.SkipTest(f"this environment does not permit loopback binds: {exc}") from exc
        cls.server.daemon_threads = True
        cls.server.requests_seen = []
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/dummy-resource"
        cls.policy = FetchPolicy(
            allowed_ips=frozenset({"127.0.0.1"}),
            allowed_ports=frozenset({cls.server.server_port}),
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self) -> None:
        self.server.requests_seen.clear()

    def test_exactly_allowed_local_fixture_remains_fetchable_through_each_client(self) -> None:
        clients = (
            ("Requests", lambda: SafeRequestsSession(policy=self.policy).get(self.url, timeout=1)),
            ("HTTPX sync", lambda: SafeClient(policy=self.policy).get(self.url, timeout=1)),
            ("HTTPX async", lambda: asyncio.run(self._httpx_async_get())),
            ("aiohttp", lambda: asyncio.run(self._aiohttp_get())),
            ("urllib", lambda: SafeUrllibOpener(self.policy).open(self.url, timeout=1)),
            ("urllib3", lambda: SafeUrllib3Client(self.policy).request("GET", self.url, timeout=1)),
        )
        for name, request in clients:
            with self.subTest(client=name):
                result = request()
                if name == "urllib":
                    with result:
                        status, body = result.status, result.read()
                elif name == "HTTPX async":
                    status, body = result
                elif name == "aiohttp":
                    status, body = result
                elif name == "urllib3":
                    status, body = result.status, result.data
                else:
                    status, body = result.status_code, result.content
                self.assertEqual(status, 200)
                self.assertEqual(body, _BODY)

        self.assertEqual(len(self.server.requests_seen), 6)
        self.assertTrue(all(path == "/dummy-resource" for path, _ in self.server.requests_seen))

    async def _httpx_async_get(self) -> tuple[int, bytes]:
        async with SafeAsyncClient(policy=self.policy) as client:
            response = await client.get(self.url, timeout=1)
            return response.status_code, response.content

    async def _aiohttp_get(self) -> tuple[int, bytes]:
        async with safe_aiohttp_session(policy=self.policy) as session:
            async with session.get(self.url, timeout=1) as response:
                return response.status, await response.read()


if __name__ == "__main__":
    unittest.main()
