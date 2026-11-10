from __future__ import annotations

import ipaddress
import socket
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from safe_egress import FetchPolicy, FetchResponse, PolicyError
from safe_egress.adapters.urllib import SafeUrllibOpener, SafeUrllibError


class SafeUrllibOpenerTests(unittest.TestCase):
    def test_public_resource_returns_urlopen_style_buffered_response(self) -> None:
        opener = SafeUrllibOpener()
        public_ip = ipaddress.ip_address("93.184.216.34")
        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (str(public_ip), 443))]

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            self.assertEqual(address, public_ip)
            self.assertEqual(method, "GET")
            return FetchResponse(
                200,
                (("Content-Type", "text/plain"), ("X-Fixture", "dummy")),
                b"PUBLIC_FIXTURE_CONTENT",
                target.url,
                (),
                method,
            )

        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            opener.fetcher, "_send", side_effect=simulated_send
        ):
            with opener.open("https://public.example/resource") as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.geturl(), "https://public.example/resource")
                self.assertEqual(response.headers.get("X-Fixture"), "dummy")
                self.assertEqual(response.read(), b"PUBLIC_FIXTURE_CONTENT")

    def test_redirect_to_loopback_is_rejected_before_second_send(self) -> None:
        opener = SafeUrllibOpener()
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

        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))]
        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            opener.fetcher, "_send", side_effect=simulated_send
        ):
            with self.assertRaises(SafeUrllibError):
                opener.open("https://public.example/start")

        self.assertEqual(sent, ["https://public.example/start"])

    def test_cross_origin_redirect_strips_configured_secret_headers(self) -> None:
        policy = FetchPolicy(additional_sensitive_headers=frozenset({"X-Company-Secret"}))
        opener = SafeUrllibOpener(policy=policy)
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
        request = urllib.request.Request(
            "https://public.example/start",
            headers={
                "X-API-Key": "dummy-api-key",
                "X-Aws-Ec2-Metadata-Token": "dummy-imdsv2-token",
                "X-Company-Secret": "dummy-secret",
            },
        )
        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            opener.fetcher, "_send", side_effect=simulated_send
        ):
            response = opener.open(request)

        with response:
            self.assertEqual(response.read(), b"PUBLIC_FIXTURE_CONTENT")
        self.assertIn("x-api-key", sent[0][1])
        self.assertIn("x-aws-ec2-metadata-token", sent[0][1])
        self.assertIn("x-company-secret", sent[0][1])
        self.assertNotIn("x-api-key", sent[1][1])
        self.assertNotIn("x-aws-ec2-metadata-token", sent[1][1])
        self.assertNotIn("x-company-secret", sent[1][1])

    def test_prepared_request_method_body_and_headers_are_preserved(self) -> None:
        policy = FetchPolicy(allowed_hosts=frozenset({"public.example"}))
        opener = SafeUrllibOpener(policy=policy)
        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))]
        calls = []

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            test_header = next((value for name, value in headers.items() if name.lower() == "x-test"), None)
            calls.append((target.url, method, body, test_header, timeout_seconds))
            return FetchResponse(200, (), b"ok", target.url, (), method)

        request = urllib.request.Request(
            "https://public.example/submit",
            data=b"dummy body",
            headers={"X-Test": "fixture"},
            method="PUT",
        )
        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            opener.fetcher, "_send", side_effect=simulated_send
        ):
            response = opener.open(request, timeout=3)

        with response:
            self.assertEqual(response.read(), b"ok")
        self.assertEqual(calls, [("https://public.example/submit", "PUT", b"dummy body", "fixture", 3.0)])

    def test_per_request_policy_override_can_target_an_exact_local_fixture(self) -> None:
        opener = SafeUrllibOpener()
        policy = FetchPolicy(
            allowed_ips=frozenset({"127.0.0.1"}),
            allowed_ports=frozenset({80}),
        )
        local_ip = ipaddress.ip_address("127.0.0.1")

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None, **kwargs):
            del headers, body, timeout_seconds, kwargs
            self.assertEqual(address, local_ip)
            return FetchResponse(200, (), b"CONTROLLED_LOCAL_FIXTURE", target.url, (), method)

        with patch.object(opener.fetcher, "_send", side_effect=simulated_send):
            with opener.open("http://127.0.0.1/status", policy=policy) as response:
                self.assertEqual(response.read(), b"CONTROLLED_LOCAL_FIXTURE")
            with self.assertRaises(SafeUrllibError):
                opener.open("http://127.0.0.1/status")

    def test_http_error_status_raises_standard_http_error_with_body(self) -> None:
        opener = SafeUrllibOpener()
        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))]

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            return FetchResponse(404, (("X-Fixture", "not-found"),), b"missing fixture", target.url, (), method)

        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            opener.fetcher, "_send", side_effect=simulated_send
        ):
            with self.assertRaises(urllib.error.HTTPError) as raised:
                opener.open("https://public.example/missing")

        try:
            self.assertEqual(raised.exception.code, 404)
            self.assertEqual(raised.exception.headers.get("X-Fixture"), "not-found")
            self.assertEqual(raised.exception.read(), b"missing fixture")
        finally:
            raised.exception.close()

    def test_custom_tls_context_and_unsupported_options_fail_closed(self) -> None:
        opener = SafeUrllibOpener()
        with self.assertRaises(PolicyError):
            opener.open("https://public.example/", context=object())
        with self.assertRaises(PolicyError):
            opener.open("https://public.example/", cafile="custom.pem")
        with self.assertRaises(SafeUrllibError):
            opener.open("ftp://public.example/file")

    def test_file_url_reads_only_dummy_fixture_with_stdlib_and_is_rejected_by_safe_opener(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory, "dummy-jwks.json")
            fixture.write_text('{"keys":[],"fixture":"dummy"}', encoding="utf-8")
            file_url = fixture.as_uri()

            # The vulnerable library behavior is the standard opener's
            # built-in FileHandler. This reads only a file created by this test.
            with urllib.request.urlopen(file_url) as response:
                self.assertIn(b'"fixture":"dummy"', response.read())

            # Safe HTTP fetches never permit local file handlers or file reads.
            with self.assertRaises(SafeUrllibError):
                SafeUrllibOpener().open(file_url)
