from __future__ import annotations

import asyncio
import ipaddress
import socket
import unittest
from unittest.mock import Mock, patch

try:
    import httpx
except ImportError:  # pragma: no cover - optional test dependency
    httpx = None

from safe_egress import FetchPolicy, FetchResponse, SafeFetcher


@unittest.skipIf(httpx is None, "install safe-egress[httpx] to run HTTPX adapter tests")
class SafeHTTPXTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_httpx_redirect_is_rejected_before_internal_transport(self) -> None:
        from safe_egress.httpx_adapter import SafeAsyncClient

        locations = (
            "http://127.0.0.1:43127/internal-status",
            "//127.0.0.1:43127/internal-status",
        )
        for location in locations:
            with self.subTest(location=location):
                fetcher = SafeFetcher()
                sent: list[str] = []

                def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
                    sent.append(target.url)
                    return FetchResponse(302, (("Location", location),), b"", target.url, (), method)

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

    async def test_async_httpx_public_fetch_falls_back_after_connection_setup_failure(self) -> None:
        from safe_egress.httpx_adapter import SafeAsyncClient

        fetcher = SafeFetcher()
        first_ip = ipaddress.ip_address("2606:4700:4700::1111")
        second_ip = ipaddress.ip_address("93.184.216.34")
        records = [
            (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (str(first_ip), 80, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (str(second_ip), 80)),
        ]

        first_connection = Mock()
        first_connection.connect.side_effect = OSError("synthetic connect failure")
        second_connection = Mock()
        fixture_response = Mock(status=200)
        fixture_response.read.return_value = b"PUBLIC_FIXTURE_CONTENT"
        fixture_response.getheaders.return_value = [("Content-Type", "text/plain")]
        second_connection.getresponse.return_value = fixture_response

        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch(
            "safe_egress.client._PinnedHTTPConnection",
            side_effect=(first_connection, second_connection),
        ):
            async with SafeAsyncClient(fetcher=fetcher) as client:
                response = await client.get("http://public.example/resource")

        first_connection.request.assert_not_called()
        second_connection.connect.assert_called_once()
        second_connection.request.assert_called_once()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "PUBLIC_FIXTURE_CONTENT")

    async def test_httpx_unicode_dot_ipv4_alias_is_rejected_before_transport(self) -> None:
        from safe_egress.httpx_adapter import SafeAsyncClient

        fetcher = SafeFetcher()
        with patch.object(fetcher, "_send") as send:
            async with SafeAsyncClient(fetcher=fetcher) as client:
                with self.assertRaises(httpx.ConnectError):
                    await client.get("http://127。0。0。1/internal-status")

        send.assert_not_called()

    async def test_async_request_accepts_trusted_per_request_policy(self) -> None:
        from safe_egress.httpx_adapter import SafeAsyncClient

        fetcher = SafeFetcher()
        policy = FetchPolicy(
            allowed_ips=frozenset({"127.0.0.1"}),
            allowed_ports=frozenset({80}),
        )
        local_ip = ipaddress.ip_address("127.0.0.1")
        sent: list[str] = []

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None, policy=None):
            del headers, body, timeout_seconds
            self.assertIs(policy, expected_policy)
            self.assertEqual(address, local_ip)
            sent.append(target.url)
            return FetchResponse(200, (), b"CONTROLLED_LOCAL_FIXTURE", target.url, (), method)

        expected_policy = policy
        with patch.object(fetcher, "_send", side_effect=simulated_send):
            async with SafeAsyncClient(fetcher=fetcher) as client:
                response = await client.request(
                    "GET", "http://127.0.0.1/status", policy=policy
                )
                with self.assertRaises(httpx.ConnectError):
                    await client.request("GET", "http://127.0.0.1/status")

        self.assertEqual(response.content, b"CONTROLLED_LOCAL_FIXTURE")
        self.assertEqual(sent, ["http://127.0.0.1/status"])

    async def test_async_per_request_policy_is_carried_across_redirects(self) -> None:
        from safe_egress.httpx_adapter import SafeAsyncClient

        policy = FetchPolicy(
            allowed_hosts=frozenset({"public.example", "other.example"}),
            additional_sensitive_headers=frozenset({"X-Company-Secret"}),
        )
        fetcher = SafeFetcher()
        sent: list[tuple[str, dict[str, str]]] = []

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None, policy=None):
            del address, body, timeout_seconds
            self.assertIs(policy, expected_policy)
            sent.append((target.host, {name.lower(): value for name, value in headers.items()}))
            if target.host == "public.example":
                return FetchResponse(302, (("Location", "https://other.example/next"),), b"", target.url, (), method)
            return FetchResponse(200, (), b"PUBLIC_FIXTURE_CONTENT", target.url, (), method)

        expected_policy = policy
        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))]
        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            fetcher, "_send", side_effect=simulated_send
        ):
            async with SafeAsyncClient(fetcher=fetcher, follow_redirects=True) as client:
                response = await client.request(
                    "GET",
                    "https://public.example/start",
                    headers={"X-Company-Secret": "dummy-secret"},
                    policy=policy,
                )

        self.assertEqual(response.content, b"PUBLIC_FIXTURE_CONTENT")
        self.assertIn("x-company-secret", sent[0][1])
        self.assertNotIn("x-company-secret", sent[1][1])

    async def test_concurrent_async_calls_do_not_share_request_policies(self) -> None:
        from safe_egress.httpx_adapter import SafeAsyncClient

        fetcher = SafeFetcher()
        policies = {
            "127.0.0.1": FetchPolicy(
                allowed_ips=frozenset({"127.0.0.1"}),
                allowed_ports=frozenset({80}),
            ),
            "127.0.0.2": FetchPolicy(
                allowed_ips=frozenset({"127.0.0.2"}),
                allowed_ports=frozenset({80}),
            ),
        }
        observed: list[tuple[str, FetchPolicy | None]] = []

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None, policy=None):
            del headers, body, timeout_seconds
            observed.append((target.host, policy))
            self.assertEqual(address, ipaddress.ip_address(target.host))
            return FetchResponse(200, (), target.host.encode(), target.url, (), method)

        with patch.object(fetcher, "_send", side_effect=simulated_send):
            async with SafeAsyncClient(fetcher=fetcher) as client:
                responses = await asyncio.gather(
                    client.request("GET", "http://127.0.0.1/one", policy=policies["127.0.0.1"]),
                    client.request("GET", "http://127.0.0.2/two", policy=policies["127.0.0.2"]),
                )

        self.assertEqual([response.content for response in responses], [b"127.0.0.1", b"127.0.0.2"])
        self.assertEqual(set(observed), set(policies.items()))

    async def test_async_httpx_removes_authorization_on_cross_origin_redirect(self) -> None:
        from safe_egress.httpx_adapter import SafeAsyncClient

        fetcher = SafeFetcher(
            FetchPolicy(additional_sensitive_headers=frozenset({"X-Company-Secret"}))
        )
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
                        "Referer": "https://public.example/page?token=dummy",
                        "X-API-Key": "dummy-api-key",
                        "X-Aws-Ec2-Metadata-Token": "dummy-imdsv2-token",
                        "X-Company-Secret": "dummy-custom-secret",
                    },
                )

        self.assertEqual(response.text, "PUBLIC_FIXTURE_CONTENT")
        self.assertIn("authorization", sent[0][1])
        self.assertIn("cookie", sent[0][1])
        self.assertIn("origin", sent[0][1])
        self.assertIn("referer", sent[0][1])
        self.assertIn("x-api-key", sent[0][1])
        self.assertIn("x-aws-ec2-metadata-token", sent[0][1])
        self.assertIn("x-company-secret", sent[0][1])
        self.assertNotIn("authorization", sent[1][1])
        self.assertNotIn("cookie", sent[1][1])
        self.assertNotIn("origin", sent[1][1])
        self.assertNotIn("referer", sent[1][1])
        self.assertNotIn("x-api-key", sent[1][1])
        self.assertNotIn("x-aws-ec2-metadata-token", sent[1][1])
        self.assertNotIn("x-company-secret", sent[1][1])

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

    async def test_async_httpx_cookie_jar_does_not_send_domain_cookie_across_origins(self) -> None:
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
                client.cookies.set("session", "dummy-cookie", domain=".example", path="/")
                response = await client.get("https://public.example/start")

        self.assertEqual(response.text, "PUBLIC_FIXTURE_CONTENT")
        self.assertIn("cookie", sent[0][1])
        self.assertNotIn("cookie", sent[1][1])

    async def test_async_httpx_cookie_jar_is_preserved_on_same_origin_redirect(self) -> None:
        from safe_egress.httpx_adapter import SafeAsyncClient

        fetcher = SafeFetcher()
        sent: list[dict[str, str]] = []

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            del address, body, timeout_seconds
            sent.append({key.lower(): value for key, value in headers.items()})
            if target.request_target == "/start":
                return FetchResponse(302, (("Location", "/next"),), b"", target.url, (), method)
            return FetchResponse(200, (), b"PUBLIC_FIXTURE_CONTENT", target.url, (), method)

        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))]
        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            fetcher, "_send", side_effect=simulated_send
        ):
            async with SafeAsyncClient(fetcher=fetcher, follow_redirects=True) as client:
                client.cookies.set("session", "dummy-cookie", domain=".example", path="/")
                response = await client.get("https://public.example/start")

        self.assertEqual(response.text, "PUBLIC_FIXTURE_CONTENT")
        self.assertTrue(all("cookie" in headers for headers in sent))

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
    def test_sync_httpx_public_fetch_falls_back_after_connection_setup_failure(self) -> None:
        from safe_egress.httpx_adapter import SafeClient

        fetcher = SafeFetcher()
        first_ip = ipaddress.ip_address("2606:4700:4700::1111")
        second_ip = ipaddress.ip_address("93.184.216.34")
        records = [
            (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (str(first_ip), 80, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (str(second_ip), 80)),
        ]

        first_connection = Mock()
        first_connection.connect.side_effect = OSError("synthetic connect failure")
        second_connection = Mock()
        fixture_response = Mock(status=200)
        fixture_response.read.return_value = b"PUBLIC_FIXTURE_CONTENT"
        fixture_response.getheaders.return_value = [("Content-Type", "text/plain")]
        second_connection.getresponse.return_value = fixture_response

        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch(
            "safe_egress.client._PinnedHTTPConnection",
            side_effect=(first_connection, second_connection),
        ):
            with SafeClient(fetcher=fetcher) as client:
                response = client.get("http://public.example/resource")

        first_connection.request.assert_not_called()
        second_connection.connect.assert_called_once()
        second_connection.request.assert_called_once()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "PUBLIC_FIXTURE_CONTENT")
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

    def test_sync_request_accepts_trusted_per_request_policy(self) -> None:
        from safe_egress.httpx_adapter import SafeClient

        fetcher = SafeFetcher()
        policy = FetchPolicy(
            allowed_ips=frozenset({"127.0.0.1"}),
            allowed_ports=frozenset({80}),
        )
        local_ip = ipaddress.ip_address("127.0.0.1")
        sent: list[str] = []

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None, policy=None):
            del headers, body, timeout_seconds
            self.assertIs(policy, expected_policy)
            self.assertEqual(address, local_ip)
            sent.append(target.url)
            return FetchResponse(200, (), b"CONTROLLED_LOCAL_FIXTURE", target.url, (), method)

        expected_policy = policy
        with patch.object(fetcher, "_send", side_effect=simulated_send):
            with SafeClient(fetcher=fetcher) as client:
                response = client.request("GET", "http://127.0.0.1/status", policy=policy)
                with self.assertRaises(httpx.ConnectError):
                    client.request("GET", "http://127.0.0.1/status")

        self.assertEqual(response.content, b"CONTROLLED_LOCAL_FIXTURE")
        self.assertEqual(sent, ["http://127.0.0.1/status"])

    def test_sync_httpx_removes_authorization_on_cross_origin_redirect(self) -> None:
        from safe_egress.httpx_adapter import SafeClient

        fetcher = SafeFetcher(
            FetchPolicy(additional_sensitive_headers=frozenset({"X-Company-Secret"}))
        )
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
                        "Referer": "https://public.example/page?token=dummy",
                        "X-API-Key": "dummy-api-key",
                        "X-Aws-Ec2-Metadata-Token": "dummy-imdsv2-token",
                        "X-Company-Secret": "dummy-custom-secret",
                    },
                )

        self.assertEqual(response.text, "PUBLIC_FIXTURE_CONTENT")
        self.assertIn("authorization", sent[0][1])
        self.assertIn("cookie", sent[0][1])
        self.assertIn("origin", sent[0][1])
        self.assertIn("referer", sent[0][1])
        self.assertIn("x-api-key", sent[0][1])
        self.assertIn("x-aws-ec2-metadata-token", sent[0][1])
        self.assertIn("x-company-secret", sent[0][1])
        self.assertNotIn("authorization", sent[1][1])
        self.assertNotIn("cookie", sent[1][1])
        self.assertNotIn("origin", sent[1][1])
        self.assertNotIn("referer", sent[1][1])
        self.assertNotIn("x-api-key", sent[1][1])
        self.assertNotIn("x-aws-ec2-metadata-token", sent[1][1])
        self.assertNotIn("x-company-secret", sent[1][1])

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

    def test_sync_httpx_cookie_jar_does_not_send_domain_cookie_across_origins(self) -> None:
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
                client.cookies.set("session", "dummy-cookie", domain=".example", path="/")
                response = client.get("https://public.example/start")

        self.assertEqual(response.text, "PUBLIC_FIXTURE_CONTENT")
        self.assertIn("cookie", sent[0][1])
        self.assertNotIn("cookie", sent[1][1])

    def test_sync_httpx_cookie_jar_is_preserved_on_same_origin_redirect(self) -> None:
        from safe_egress.httpx_adapter import SafeClient

        fetcher = SafeFetcher()
        sent: list[dict[str, str]] = []

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            del address, body, timeout_seconds
            sent.append({key.lower(): value for key, value in headers.items()})
            if target.request_target == "/start":
                return FetchResponse(302, (("Location", "/next"),), b"", target.url, (), method)
            return FetchResponse(200, (), b"PUBLIC_FIXTURE_CONTENT", target.url, (), method)

        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))]
        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            fetcher, "_send", side_effect=simulated_send
        ):
            with SafeClient(fetcher=fetcher, follow_redirects=True) as client:
                client.cookies.set("session", "dummy-cookie", domain=".example", path="/")
                response = client.get("https://public.example/start")

        self.assertEqual(response.text, "PUBLIC_FIXTURE_CONTENT")
        self.assertTrue(all("cookie" in headers for headers in sent))

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
