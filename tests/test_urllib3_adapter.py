from __future__ import annotations

import gzip
import ipaddress
import json
import socket
import unittest
from unittest.mock import Mock, patch

try:
    import urllib3
except ImportError:  # pragma: no cover - optional test dependency
    urllib3 = None

from safe_egress import FetchPolicy, FetchResponse, PolicyError


@unittest.skipIf(urllib3 is None, "install safe-egress[urllib3] to run urllib3 adapter tests")
class SafeUrllib3ClientTests(unittest.TestCase):
    def test_public_resource_request_returns_urllib3_response(self) -> None:
        from safe_egress.urllib3_adapter import SafeUrllib3Client

        client = SafeUrllib3Client()
        public_ip = ipaddress.ip_address("93.184.216.34")
        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (str(public_ip), 443))]

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            self.assertEqual(address, public_ip)
            self.assertEqual(method, "GET")
            return FetchResponse(
                200,
                (("Content-Type", "text/plain"), ("X-Fixture", "one"), ("X-Fixture", "two")),
                b"PUBLIC_FIXTURE_CONTENT",
                target.url,
                (),
                method,
            )

        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            client.fetcher, "_send", side_effect=simulated_send
        ):
            response = client.request("GET", "https://public.example/resource")

        self.assertIsInstance(response, urllib3.response.HTTPResponse)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.data, b"PUBLIC_FIXTURE_CONTENT")
        self.assertEqual(response.headers.getlist("X-Fixture"), ["one", "two"])
        self.assertEqual(response.geturl(), "https://public.example/resource")

    def test_compressed_response_is_decoded_under_policy_limit(self) -> None:
        from safe_egress.urllib3_adapter import SafeUrllib3Client

        client = SafeUrllib3Client(policy=FetchPolicy(max_response_bytes=1024))
        compressed = gzip.compress(b"PUBLIC_GZIP_FIXTURE")
        fake_response = Mock(status=200)
        fake_response.read.return_value = compressed
        fake_response.getheaders.return_value = [
            ("Content-Encoding", "gzip"),
            ("Content-Length", str(len(compressed))),
        ]
        connection = Mock()
        connection.getresponse.return_value = fake_response
        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 80))]

        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch(
            "safe_egress.client._PinnedHTTPConnection", return_value=connection
        ):
            response = client.request("GET", "http://public.example/resource")

        self.assertEqual(response.data, b"PUBLIC_GZIP_FIXTURE")
        self.assertIsNone(response.headers.get("Content-Encoding"))
        self.assertEqual(response.headers.get("Content-Length"), str(len(response.data)))

    def test_compressed_expansion_over_policy_limit_is_rejected(self) -> None:
        from safe_egress.urllib3_adapter import SafeUrllib3Client, SafeUrllib3Error

        client = SafeUrllib3Client(policy=FetchPolicy(max_response_bytes=1024))
        compressed = gzip.compress(b"A" * 100_000)
        self.assertLess(len(compressed), 1024)
        fake_response = Mock(status=200)
        fake_response.read.return_value = compressed
        fake_response.getheaders.return_value = [("Content-Encoding", "gzip")]
        connection = Mock()
        connection.getresponse.return_value = fake_response
        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 80))]

        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch(
            "safe_egress.client._PinnedHTTPConnection", return_value=connection
        ):
            with self.assertRaises(SafeUrllib3Error):
                client.request("GET", "http://public.example/resource")
        connection.close.assert_called_once()

    def test_redirect_to_loopback_is_rejected_before_second_send(self) -> None:
        from safe_egress.urllib3_adapter import SafeUrllib3Client, SafeUrllib3Error

        client = SafeUrllib3Client()
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
            client.fetcher, "_send", side_effect=simulated_send
        ):
            with self.assertRaises(SafeUrllib3Error):
                client.request("GET", "https://public.example/start")

        self.assertEqual(sent, ["https://public.example/start"])

    def test_cross_origin_redirect_strips_configured_secret_headers(self) -> None:
        from safe_egress.urllib3_adapter import SafeUrllib3Client

        policy = FetchPolicy(additional_sensitive_headers=frozenset({"X-Company-Secret"}))
        client = SafeUrllib3Client(policy=policy)
        sent: list[tuple[str, dict[str, str]]] = []

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            del address, body, timeout_seconds
            sent.append((target.url, {name.lower(): value for name, value in headers.items()}))
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
            client.fetcher, "_send", side_effect=simulated_send
        ):
            response = client.request(
                "GET",
                "https://public.example/start",
                headers={
                    "X-API-Key": "dummy-api-key",
                    "X-Aws-Ec2-Metadata-Token": "dummy-imdsv2-token",
                    "X-Company-Secret": "dummy-secret",
                },
            )

        self.assertEqual(response.data, b"PUBLIC_FIXTURE_CONTENT")
        self.assertIn("x-api-key", sent[0][1])
        self.assertIn("x-aws-ec2-metadata-token", sent[0][1])
        self.assertIn("x-company-secret", sent[0][1])
        self.assertNotIn("x-api-key", sent[1][1])
        self.assertNotIn("x-aws-ec2-metadata-token", sent[1][1])
        self.assertNotIn("x-company-secret", sent[1][1])

    def test_json_body_and_policy_supported_request_options(self) -> None:
        from safe_egress.urllib3_adapter import SafeUrllib3Client

        policy = FetchPolicy(allowed_hosts=frozenset({"public.example"}))
        client = SafeUrllib3Client(policy=policy)
        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))]
        calls = []

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            calls.append((method, body, headers["Content-Type"], timeout_seconds))
            return FetchResponse(201, (), b"created", target.url, (), method)

        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            client.fetcher, "_send", side_effect=simulated_send
        ):
            response = client.request(
                "POST",
                "https://public.example/items",
                json={"key": "dummy"},
                timeout=2,
                redirect=False,
            )

        self.assertEqual(response.status, 201)
        self.assertEqual(calls[0][0], "POST")
        self.assertEqual(json.loads(calls[0][1]), {"key": "dummy"})
        self.assertEqual(calls[0][2], "application/json")
        self.assertEqual(calls[0][3], 2)

    def test_per_request_policy_override_is_rechecked_for_request(self) -> None:
        from safe_egress.urllib3_adapter import SafeUrllib3Client, SafeUrllib3Error

        client = SafeUrllib3Client()
        policy = FetchPolicy(
            allowed_ips=frozenset({"127.0.0.1"}),
            allowed_ports=frozenset({80}),
        )
        local_ip = ipaddress.ip_address("127.0.0.1")

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None, **kwargs):
            del headers, body, timeout_seconds, kwargs
            self.assertEqual(address, local_ip)
            return FetchResponse(200, (), b"CONTROLLED_LOCAL_FIXTURE", target.url, (), method)

        with patch.object(client.fetcher, "_send", side_effect=simulated_send):
            response = client.request(
                "GET", "http://127.0.0.1/status", policy=policy
            )
            with self.assertRaises(SafeUrllib3Error):
                client.request("GET", "http://127.0.0.1/status")

        self.assertEqual(response.data, b"CONTROLLED_LOCAL_FIXTURE")

    def test_urllib3_compat_pool_manager_accepts_per_request_policy(self) -> None:
        from safe_egress.urllib3_compat import PoolManager

        manager = PoolManager()
        policy = FetchPolicy(
            allowed_ips=frozenset({"127.0.0.1"}),
            allowed_ports=frozenset({80}),
        )
        local_ip = ipaddress.ip_address("127.0.0.1")

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None, **kwargs):
            del headers, body, timeout_seconds, kwargs
            self.assertEqual(address, local_ip)
            return FetchResponse(200, (), b"CONTROLLED_LOCAL_FIXTURE", target.url, (), method)

        with patch.object(manager._client.fetcher, "_send", side_effect=simulated_send):
            response = manager.request(
                "GET", "http://127.0.0.1/status", policy=policy
            )

        self.assertEqual(response.data, b"CONTROLLED_LOCAL_FIXTURE")

    def test_per_request_policy_applies_its_request_body_limit(self) -> None:
        from safe_egress.errors import RequestTooLargeError
        from safe_egress.urllib3_adapter import SafeUrllib3Client

        client = SafeUrllib3Client()
        policy = FetchPolicy(max_request_bytes=4)
        with patch.object(client.fetcher, "_send") as send:
            with self.assertRaises(RequestTooLargeError):
                client.request("POST", "https://public.example/upload", body=b"12345", policy=policy)
        send.assert_not_called()

    def test_unsupported_bypass_or_streaming_options_fail_closed(self) -> None:
        from safe_egress.urllib3_adapter import SafeUrllib3Client

        client = SafeUrllib3Client()
        for options in (
            {"proxy_url": "http://proxy.example"},
            {"fields": {"file": "data"}},
            {"preload_content": False},
            {"chunked": True},
        ):
            with self.subTest(options=options), self.assertRaises(PolicyError):
                client.request("GET", "https://public.example/", **options)

    def test_urllib3_compat_pool_manager_blocks_loopback_redirect(self) -> None:
        from safe_egress.urllib3_compat import PoolManager

        manager = PoolManager()
        sent: list[str] = []

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            del address, headers, body, timeout_seconds
            sent.append(target.url)
            return FetchResponse(
                302,
                (("Location", "http://127.0.0.1/internal-status"),),
                b"",
                target.url,
                (),
                method,
            )

        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 80))]
        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            manager._client.fetcher, "_send", side_effect=simulated_send
        ):
            with self.assertRaises(urllib3.exceptions.HTTPError):
                manager.request("GET", "http://public.example/start")

        self.assertEqual(sent, ["http://public.example/start"])

    def test_urllib3_compat_public_fetch_and_unknown_pool_options(self) -> None:
        from safe_egress.urllib3_compat import PoolManager, request as urllib3_request

        with self.assertRaises(PolicyError):
            PoolManager(retries=0)

        manager = PoolManager()
        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 80))]

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            del address, headers, body, timeout_seconds
            return FetchResponse(200, (), b"PUBLIC_FIXTURE_CONTENT", target.url, (), method)

        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            manager._client.fetcher, "_send", side_effect=simulated_send
        ):
            response = manager.request("GET", "http://public.example/document")

        self.assertEqual(response.data, b"PUBLIC_FIXTURE_CONTENT")

        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch(
            "safe_egress.client.SafeFetcher._send", side_effect=simulated_send
        ):
            module_response = urllib3_request(
                "GET",
                "http://public.example/module-level",
                policy=FetchPolicy(allowed_hosts=frozenset({"public.example"})),
            )

        self.assertEqual(module_response.data, b"PUBLIC_FIXTURE_CONTENT")
