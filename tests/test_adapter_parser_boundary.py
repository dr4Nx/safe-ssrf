from __future__ import annotations

import asyncio
import socket
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

from safe_egress import PolicyError
from safe_egress.aiohttp_adapter import safe_aiohttp_session
from safe_egress.httpx_adapter import SafeAsyncClient, SafeClient
from safe_egress.requests_adapter import SafeRequestsSession
from safe_egress.urllib3_adapter import SafeUrllib3Client
from safe_egress.urllib_adapter import SafeUrllibOpener


_LOOPBACK_RECORDS = [
    (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 80))
]
_CONFUSING_URLS = (
    "http://127.1/dummy",
    "http://0177.0.0.1/dummy",
    "http://0x7f000001/dummy",
    "http://2130706433/dummy",
    "http://127。0。0。1/dummy",
    r"http://attacker.example\@127.0.0.1/dummy",
)


class ClientParserBoundaryTests(unittest.TestCase):
    """Client URL parsing must not hide a local destination from Safe Egress."""

    def test_confusing_loopback_spellings_are_rejected_by_every_adapter(self) -> None:
        clients = (
            ("Requests", requests.RequestException, self._requests_get),
            ("HTTPX sync", (httpx.RequestError, httpx.InvalidURL), self._httpx_sync_get),
            ("HTTPX async", (httpx.RequestError, httpx.InvalidURL), self._httpx_async_get),
            ("aiohttp", (aiohttp.ClientError, PolicyError, ValueError), self._aiohttp_get),
            ("urllib", urllib.error.URLError, self._urllib_get),
            ("urllib3", urllib3.exceptions.HTTPError, self._urllib3_get),
        )

        # Some clients reject these inputs during parsing; others normalize
        # them or pass them to the resolver. Either way, none may reach a
        # socket. Return loopback for every hostname that is resolved so the
        # test remains independent of OS-specific numeric-hostname behavior.
        with patch("socket.getaddrinfo", return_value=_LOOPBACK_RECORDS), patch(
            "socket.socket.connect", side_effect=AssertionError("unexpected socket connect")
        ) as connect, patch(
            "socket.socket.connect_ex", side_effect=AssertionError("unexpected socket connect_ex")
        ) as connect_ex:
            for url in _CONFUSING_URLS:
                for name, expected_error, request in clients:
                    with self.subTest(url=url, client=name):
                        try:
                            with self.assertRaises(expected_error):
                                request(url)
                        except AssertionError as exc:
                            raise AssertionError(f"unexpected rejection behavior for {name} with {url}: {exc}") from exc

            connect.assert_not_called()
            connect_ex.assert_not_called()

    def _requests_get(self, url: str) -> None:
        with SafeRequestsSession() as client:
            client.get(url, timeout=1)

    def _httpx_sync_get(self, url: str) -> None:
        with SafeClient() as client:
            client.get(url, timeout=1)

    def _httpx_async_get(self, url: str) -> None:
        async def request() -> None:
            async with SafeAsyncClient() as client:
                await client.get(url, timeout=1)

        asyncio.run(request())

    def _aiohttp_get(self, url: str) -> None:
        async def request() -> None:
            async with safe_aiohttp_session() as client:
                async with client.get(url, timeout=1):
                    self.fail("aiohttp returned a response for a local URL")

        asyncio.run(request())

    def _urllib_get(self, url: str) -> None:
        with SafeUrllibOpener().open(url, timeout=1):
            self.fail("urllib returned a response for a local URL")

    def _urllib3_get(self, url: str) -> None:
        SafeUrllib3Client().request("GET", url, timeout=1)


if __name__ == "__main__":
    unittest.main()
