from __future__ import annotations

import ipaddress
import json
import socket
import unittest
from unittest.mock import patch

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
