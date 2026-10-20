from __future__ import annotations

import ipaddress
import socket
import unittest
from unittest.mock import patch

try:
    import httpx
except ImportError:  # pragma: no cover - optional test dependency
    httpx = None

from safe_egress import FetchPolicy, FetchResponse, SafeFetcher


@unittest.skipIf(httpx is None, "install safe-egress[httpx] to run HTTPX adapter tests")
class SafeHTTPXTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_httpx_redirect_is_rejected_before_internal_transport(self) -> None:
        from safe_egress.httpx_adapter import SafeAsyncClient

        fetcher = SafeFetcher()
        sent: list[str] = []

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            sent.append(target.url)
            return FetchResponse(
                302,
                (("Location", "http://127.0.0.1:43127/internal-status"),),
                b"",
                target.url,
                (),
                method,
            )

        public_records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))]
        with patch("safe_egress.client.socket.getaddrinfo", return_value=public_records), patch.object(
            fetcher, "_send", side_effect=simulated_send
        ):
            async with SafeAsyncClient(fetcher=fetcher, follow_redirects=True) as client:
                with self.assertRaises(httpx.ConnectError):
                    await client.get("https://public.example/start")

        self.assertEqual(sent, ["https://public.example/start"])

    async def test_httpx_public_get_returns_fixture_response(self) -> None:
        from safe_egress.httpx_adapter import SafeAsyncClient

        fetcher = SafeFetcher()
        public_ip = ipaddress.ip_address("93.184.216.34")
        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (str(public_ip), 443))]

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            self.assertEqual(address, public_ip)
            self.assertEqual(method, "GET")
            return FetchResponse(
                200,
                (("Content-Type", "text/plain"),),
                b"PUBLIC_FIXTURE_CONTENT",
                target.url,
                (),
                method,
            )

        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            fetcher, "_send", side_effect=simulated_send
        ):
            async with SafeAsyncClient(fetcher=fetcher) as client:
                response = await client.get("https://public.example/resource")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "PUBLIC_FIXTURE_CONTENT")
        self.assertEqual(str(response.url), "https://public.example/resource")

    async def test_async_httpx_removes_authorization_on_cross_origin_redirect(self) -> None:
        from safe_egress.httpx_adapter import SafeAsyncClient

        fetcher = SafeFetcher()
        sent: list[tuple[str, dict[str, str]]] = []

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            del address, body, timeout_seconds
            sent.append((target.host, {key.lower(): value for key, value in headers.items()}))
            if target.host == "public.example":
                return FetchResponse(
                    302,
                    (("Location", "https://other.example/next"),),
                    b"",
                    target.url,
                    (),
                    method,
                )
            return FetchResponse(200, (), b"PUBLIC_FIXTURE_CONTENT", target.url, (), method)

        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))]
        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            fetcher, "_send", side_effect=simulated_send
        ):
            async with SafeAsyncClient(fetcher=fetcher, follow_redirects=True) as client:
                response = await client.get(
                    "https://public.example/start",
                    headers={
                        "Authorization": "Bearer dummy",
                        "Cookie": "session=dummy",
                        "Origin": "https://caller.example",
                    },
                )

        self.assertEqual(response.text, "PUBLIC_FIXTURE_CONTENT")
        self.assertIn("authorization", sent[0][1])
        self.assertIn("cookie", sent[0][1])
        self.assertIn("origin", sent[0][1])
        self.assertNotIn("authorization", sent[1][1])
        self.assertNotIn("cookie", sent[1][1])
        self.assertNotIn("origin", sent[1][1])

    async def test_async_httpx_basic_auth_is_not_forwarded_across_origins(self) -> None:
        from safe_egress.httpx_adapter import SafeAsyncClient

        fetcher = SafeFetcher()
        sent: list[tuple[str, dict[str, str]]] = []

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            del address, body, timeout_seconds
            sent.append((target.host, {key.lower(): value for key, value in headers.items()}))
            if target.host == "public.example":
                return FetchResponse(
                    302,
                    (("Location", "https://other.example/next"),),
                    b"",
                    target.url,
                    (),
                    method,
                )
            return FetchResponse(200, (), b"PUBLIC_FIXTURE_CONTENT", target.url, (), method)

        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))]
        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            fetcher, "_send", side_effect=simulated_send
        ):
            async with SafeAsyncClient(
                fetcher=fetcher,
                follow_redirects=True,
                auth=("dummy-user", "dummy-password"),
            ) as client:
                response = await client.get("https://public.example/start")

        self.assertEqual(response.text, "PUBLIC_FIXTURE_CONTENT")
        self.assertIn("authorization", sent[0][1])
        self.assertNotIn("authorization", sent[1][1])

    async def test_safe_client_rejects_options_that_could_replace_its_transport(self) -> None:
        from safe_egress.httpx_adapter import SafeAsyncClient

        for options in (
            {"proxy": "http://proxy.invalid"},
            {"mounts": {"https://": httpx.MockTransport(lambda request: httpx.Response(200))}},
            {"transport": httpx.MockTransport(lambda request: httpx.Response(200))},
            {"trust_env": True},
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                SafeAsyncClient(**options)


@unittest.skipIf(httpx is None, "install safe-egress[httpx] to run HTTPX adapter tests")
class SafeHTTPXSyncTransportTests(unittest.TestCase):
    def test_sync_httpx_redirect_is_rejected_before_internal_transport(self) -> None:
        from safe_egress.httpx_adapter import SafeClient

        fetcher = SafeFetcher()
        sent: list[str] = []

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            sent.append(target.url)
            return FetchResponse(
                302,
                (("Location", "http://127.0.0.1/internal-status"),),
                b"",
                target.url,
                (),
                method,
            )

        public_records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))]
        with patch("safe_egress.client.socket.getaddrinfo", return_value=public_records), patch.object(
            fetcher, "_send", side_effect=simulated_send
        ):
            with SafeClient(fetcher=fetcher, follow_redirects=True) as client:
                with self.assertRaises(httpx.ConnectError):
                    client.get("https://public.example/start")

        self.assertEqual(sent, ["https://public.example/start"])

    def test_sync_httpx_public_get_returns_fixture_response(self) -> None:
        from safe_egress.httpx_adapter import SafeClient

        fetcher = SafeFetcher()
        public_ip = ipaddress.ip_address("93.184.216.34")
        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (str(public_ip), 443))]

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            self.assertEqual(address, public_ip)
            self.assertEqual(method, "GET")
            return FetchResponse(
                200,
                (("Content-Type", "text/plain"),),
                b"PUBLIC_FIXTURE_CONTENT",
                target.url,
                (),
                method,
            )

        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            fetcher, "_send", side_effect=simulated_send
        ):
            with SafeClient(fetcher=fetcher) as client:
                response = client.get("https://public.example/resource")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "PUBLIC_FIXTURE_CONTENT")
        self.assertEqual(str(response.url), "https://public.example/resource")

    def test_sync_httpx_removes_authorization_on_cross_origin_redirect(self) -> None:
        from safe_egress.httpx_adapter import SafeClient

        fetcher = SafeFetcher()
        sent: list[tuple[str, dict[str, str]]] = []

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            del address, body, timeout_seconds
            sent.append((target.host, {key.lower(): value for key, value in headers.items()}))
            if target.host == "public.example":
                return FetchResponse(
                    302,
                    (("Location", "https://other.example/next"),),
                    b"",
                    target.url,
                    (),
                    method,
                )
            return FetchResponse(200, (), b"PUBLIC_FIXTURE_CONTENT", target.url, (), method)

        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))]
        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            fetcher, "_send", side_effect=simulated_send
        ):
            with SafeClient(fetcher=fetcher, follow_redirects=True) as client:
                response = client.get(
                    "https://public.example/start",
                    headers={
                        "Authorization": "Bearer dummy",
                        "Cookie": "session=dummy",
                        "Origin": "https://caller.example",
                    },
                )

        self.assertEqual(response.text, "PUBLIC_FIXTURE_CONTENT")
        self.assertIn("authorization", sent[0][1])
        self.assertIn("cookie", sent[0][1])
        self.assertIn("origin", sent[0][1])
        self.assertNotIn("authorization", sent[1][1])
        self.assertNotIn("cookie", sent[1][1])
        self.assertNotIn("origin", sent[1][1])

    def test_sync_httpx_basic_auth_is_not_forwarded_across_origins(self) -> None:
        from safe_egress.httpx_adapter import SafeClient

        fetcher = SafeFetcher()
        sent: list[tuple[str, dict[str, str]]] = []

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            del address, body, timeout_seconds
            sent.append((target.host, {key.lower(): value for key, value in headers.items()}))
            if target.host == "public.example":
                return FetchResponse(
                    302,
                    (("Location", "https://other.example/next"),),
                    b"",
                    target.url,
                    (),
                    method,
                )
            return FetchResponse(200, (), b"PUBLIC_FIXTURE_CONTENT", target.url, (), method)

        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))]
        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            fetcher, "_send", side_effect=simulated_send
        ):
            with SafeClient(
                fetcher=fetcher,
                follow_redirects=True,
                auth=("dummy-user", "dummy-password"),
            ) as client:
                response = client.get("https://public.example/start")

        self.assertEqual(response.text, "PUBLIC_FIXTURE_CONTENT")
        self.assertIn("authorization", sent[0][1])
        self.assertNotIn("authorization", sent[1][1])

    def test_sync_httpx_rejects_oversized_streaming_request_before_send(self) -> None:
        from safe_egress.httpx_adapter import SafeClient

        fetcher = SafeFetcher(FetchPolicy(max_request_bytes=3))
        with patch.object(fetcher, "_send") as send:
            with SafeClient(fetcher=fetcher) as client:
                with self.assertRaises(httpx.RequestError):
                    client.post("https://public.example/upload", content=iter([b"ab", b"cd", b"ef"]))

        send.assert_not_called()

    def test_sync_client_rejects_options_that_could_replace_its_transport(self) -> None:
        from safe_egress.httpx_adapter import SafeClient

        for options in (
            {"proxy": "http://proxy.invalid"},
            {"mounts": {"https://": httpx.MockTransport(lambda request: httpx.Response(200))}},
            {"transport": httpx.MockTransport(lambda request: httpx.Response(200))},
            {"trust_env": True},
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                SafeClient(**options)
