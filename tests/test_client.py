from __future__ import annotations

import gzip
import ipaddress
import socket
import unittest
import zlib
from unittest.mock import Mock, patch

from safe_egress import (
    FetchPolicy,
    FetchResponse,
    PolicyError,
    RedirectLimitError,
    RequestTooLargeError,
    ResponseTooLargeError,
    SafeFetcher,
)
from safe_egress.client import _PinnedHTTPConnection, _PinnedHTTPSConnection


PUBLIC_IP = ipaddress.ip_address("93.184.216.34")


def response(status: int, body: bytes = b"ok", headers=()) -> FetchResponse:
    return FetchResponse(status, tuple(headers), body, "", ())


def resolver_records(*addresses: str):
    return [
        (socket.AF_INET6 if ":" in address else socket.AF_INET,
         socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443 if ":" in address else 80))
        for address in addresses
    ]


class SimulatedService:
    """In-memory fixture: no listener, DNS, or external network is used."""

    def __init__(self, status=200, body=b"dummy public-resource content", headers=()):
        self.status = status
        self.body = body
        self.headers = tuple(headers)
        self.requests = []

    def send(self, target, address, headers, *, method="GET", body=None, timeout_seconds=None):
        self.requests.append((target, address, dict(headers)))
        return response(self.status, self.body, self.headers)


class SafeFetcherTests(unittest.TestCase):
    def test_loopback_target_is_rejected_before_transport_is_called(self) -> None:
        transport = Mock()
        fetcher = SafeFetcher()
        with patch.object(fetcher, "_send", transport):
            with self.assertRaises(PolicyError):
                fetcher.get("http://127.0.0.1/internal-status")
        transport.assert_not_called()

    def test_exact_private_host_exception_can_fetch_simulated_service(self) -> None:
        service = SimulatedService()
        policy = FetchPolicy(
            allowed_hosts=frozenset({"fixture.internal"}),
            allowed_private_hosts=frozenset({"fixture.internal"}),
        )
        fetcher = SafeFetcher(policy)
        with patch("safe_egress.client.socket.getaddrinfo", return_value=resolver_records("127.0.0.1")), patch.object(
            fetcher, "_send", side_effect=service.send
        ):
            result = fetcher.get("http://fixture.internal/public-resource")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.content, b"dummy public-resource content")
        self.assertEqual(len(service.requests), 1)
        self.assertEqual(service.requests[0][0].host, "fixture.internal")
        self.assertEqual(service.requests[0][1], ipaddress.ip_address("127.0.0.1"))

    def test_private_exception_does_not_apply_to_another_hostname(self) -> None:
        policy = FetchPolicy(allowed_private_hosts=frozenset({"trusted.internal"}))
        fetcher = SafeFetcher(policy)
        transport = Mock()
        with patch("safe_egress.client.socket.getaddrinfo", return_value=resolver_records("127.0.0.1")), patch.object(
            fetcher, "_send", transport
        ):
            with self.assertRaises(PolicyError):
                fetcher.get("http://other.internal/")
        transport.assert_not_called()

    def test_private_exception_is_an_explicit_trust_of_exact_hostname(self) -> None:
        """The exception permits every resolver answer for that exact trusted name."""
        policy = FetchPolicy(allowed_private_hosts=frozenset({"trusted.internal"}))
        records = resolver_records("127.0.0.1", "169.254.169.254")
        with patch("safe_egress.client.socket.getaddrinfo", return_value=records):
            self.assertEqual(
                SafeFetcher(policy)._resolve_and_check("trusted.internal", 80),
                (ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("169.254.169.254")),
            )
        self.assertFalse(policy.permits_private("other.internal"))

    def test_public_resource_utility_path_uses_simulated_public_result(self) -> None:
        service = SimulatedService(
            body=b"simulated public page",
            headers=(("Content-Type", "text/html"), ("X-Test", "fixture")),
        )
        fetcher = SafeFetcher()
        with patch("safe_egress.client.socket.getaddrinfo", return_value=resolver_records(str(PUBLIC_IP))), patch.object(
            fetcher, "_send", side_effect=service.send
        ):
            result = fetcher.get("https://public.example/resource?q=1")

        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.content, b"simulated public page")
        self.assertEqual(result.url, "https://public.example/resource?q=1")
        self.assertIn(("Content-Type", "text/html"), result.headers)
        self.assertEqual(service.requests[0][1], PUBLIC_IP)
        self.assertEqual(service.requests[0][0].request_target, "/resource?q=1")

    def test_request_method_and_bounded_body_reach_the_pinned_transport(self) -> None:
        fetcher = SafeFetcher()
        seen = []

        def send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            seen.append((method, body, timeout_seconds))
            return response(201, b"created")

        with patch("safe_egress.client.socket.getaddrinfo", return_value=resolver_records(str(PUBLIC_IP))), patch.object(
            fetcher, "_send", side_effect=send
        ):
            result = fetcher.request("POST", "https://public.example/resource", body=b"dummy payload")

        self.assertEqual(result.status_code, 201)
        self.assertEqual(result.method, "POST")
        self.assertEqual(seen, [("POST", b"dummy payload", fetcher.policy.timeout_seconds)])

    def test_request_body_and_framing_headers_are_bounded(self) -> None:
        fetcher = SafeFetcher(FetchPolicy(max_request_bytes=4))
        with patch.object(fetcher, "_send") as send:
            with self.assertRaises(RequestTooLargeError):
                fetcher.request("POST", "http://public.example/", body=b"12345")
            with self.assertRaises(PolicyError):
                fetcher.request("POST", "http://public.example/", headers={"Content-Length": "1"}, body=b"x")
        send.assert_not_called()

    def test_post_302_becomes_get_before_the_next_checked_request(self) -> None:
        fetcher = SafeFetcher()
        seen = []

        def send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            seen.append((method, body, dict(headers)))
            if len(seen) == 1:
                return response(302, headers=(("Location", "/next"),))
            return response(200, b"done")

        with patch("safe_egress.client.socket.getaddrinfo", return_value=resolver_records(str(PUBLIC_IP))), patch.object(
            fetcher, "_send", side_effect=send
        ):
            result = fetcher.request(
                "POST",
                "https://public.example/start",
                headers={"Content-Type": "text/plain"},
                body=b"dummy payload",
            )

        self.assertEqual(result.status_code, 200)
        self.assertEqual(seen[0][0:2], ("POST", b"dummy payload"))
        self.assertEqual(seen[1][0:2], ("GET", None))
        self.assertNotIn("content-type", {key.lower() for key in seen[1][2]})

    def test_dns_failure_and_empty_answers_fail_closed(self) -> None:
        fetcher = SafeFetcher()
        for result_or_error in (OSError("controlled resolver failure"), []):
            with self.subTest(result=result_or_error), patch(
                "safe_egress.client.socket.getaddrinfo",
                side_effect=result_or_error if isinstance(result_or_error, Exception) else None,
                return_value=result_or_error if not isinstance(result_or_error, Exception) else None,
            ), patch.object(fetcher, "_send") as send:
                with self.assertRaises(PolicyError):
                    fetcher.get("http://public.example/")
                send.assert_not_called()

    def test_mixed_public_and_private_dns_answers_fail_closed(self) -> None:
        with patch(
            "safe_egress.client.socket.getaddrinfo",
            return_value=resolver_records("93.184.216.34", "10.0.0.2"),
        ), patch.object(SafeFetcher, "_send") as send:
            with self.assertRaises(PolicyError):
                SafeFetcher().get("http://public.example/")
            send.assert_not_called()

    def test_url_parser_rejects_unsafe_or_ambiguous_forms(self) -> None:
        invalid_urls = (
            "ftp://public.example/file",
            "http://user:pass@public.example/",
            "http://public.example/#fragment",
            "http://public.example/has space",
            "http://public.example\\@127.0.0.1/",
            "http://public.example%2eattacker.test/",
            "http://[not-ipv6]/",
            "http://public.example:99999/",
            "http://public.example/\nheader",
        )
        for url in invalid_urls:
            with self.subTest(url=url), self.assertRaises(PolicyError):
                SafeFetcher._parse_target(url)

    def test_alternate_numeric_hosts_are_checked_after_resolution(self) -> None:
        for host in ("127.1", "0177.0.0.1", "0x7f000001", "2130706433"):
            fetcher = SafeFetcher()
            with self.subTest(host=host), patch(
                "safe_egress.client.socket.getaddrinfo", return_value=resolver_records("127.0.0.1")
            ), patch.object(fetcher, "_send") as send:
                with self.assertRaises(PolicyError):
                    fetcher.get(f"http://{host}/")
                send.assert_not_called()

    def test_port_and_exact_host_policy_are_enforced_before_network(self) -> None:
        fetcher = SafeFetcher(FetchPolicy(allowed_hosts=frozenset({"allowed.example"})))
        with patch.object(fetcher, "_send") as send:
            with self.assertRaises(PolicyError):
                fetcher.get("http://other.example/")
            with self.assertRaises(PolicyError):
                fetcher.get("http://allowed.example:8080/")
            send.assert_not_called()

    def test_redirect_to_prohibited_loopback_is_rejected_before_second_request(self) -> None:
        first = SimulatedService(status=302, headers=(("Location", "http://127.0.0.1/internal"),))
        fetcher = SafeFetcher(FetchPolicy(allowed_private_hosts=frozenset({"start.internal"})))
        with patch("safe_egress.client.socket.getaddrinfo", return_value=resolver_records("127.0.0.1")), patch.object(
            fetcher, "_send", side_effect=first.send
        ):
            with self.assertRaises(PolicyError):
                fetcher.get("http://start.internal/start")
        self.assertEqual(len(first.requests), 1)

    def test_redirects_are_revalidated_and_cross_origin_credentials_removed(self) -> None:
        source = SimulatedService(status=302, headers=(("Location", "http://second.internal/end"),))
        destination = SimulatedService(body=b"destination response")
        allowed = {"first.internal", "second.internal"}
        policy = FetchPolicy(allowed_private_hosts=frozenset(allowed))
        fetcher = SafeFetcher(policy)

        def send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            return (source if target.host == "first.internal" else destination).send(target, address, headers)

        with patch("safe_egress.client.socket.getaddrinfo", return_value=resolver_records("127.0.0.1")), patch.object(
            fetcher, "_send", side_effect=send
        ):
            result = fetcher.get(
                "http://first.internal/start",
                headers={"Authorization": "Bearer dummy", "Cookie": "session=dummy", "Origin": "http://first.internal"},
            )

        self.assertEqual(result.content, b"destination response")
        self.assertEqual(result.history, ("http://first.internal/start",))
        self.assertIn("Authorization", source.requests[0][2])
        for sensitive in ("authorization", "cookie", "origin"):
            self.assertNotIn(sensitive, {key.lower() for key in destination.requests[0][2]})

    def test_same_origin_redirect_preserves_caller_headers(self) -> None:
        source = SimulatedService(status=302, headers=(("Location", "/next"),))
        destination = SimulatedService(body=b"done")
        fetcher = SafeFetcher(FetchPolicy(allowed_private_hosts=frozenset({"same.internal"})))

        def send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            return (source if target.request_target == "/start" else destination).send(target, address, headers)

        with patch("safe_egress.client.socket.getaddrinfo", return_value=resolver_records("127.0.0.1")), patch.object(
            fetcher, "_send", side_effect=send
        ):
            fetcher.get("http://same.internal/start", headers={"Authorization": "Bearer dummy", "Cookie": "dummy"})
        self.assertEqual(destination.requests[0][2]["Authorization"], "Bearer dummy")
        self.assertEqual(destination.requests[0][2]["Cookie"], "dummy")

    def test_redirect_limit_is_enforced(self) -> None:
        loop = SimulatedService(status=302, headers=(("Location", "/again"),))
        fetcher = SafeFetcher(FetchPolicy(allowed_private_hosts=frozenset({"loop.internal"}), max_redirects=1))
        with patch("safe_egress.client.socket.getaddrinfo", return_value=resolver_records("127.0.0.1")), patch.object(
            fetcher, "_send", side_effect=loop.send
        ):
            with self.assertRaises(RedirectLimitError):
                fetcher.get("http://loop.internal/start")
        self.assertEqual(len(loop.requests), 2)

    def test_response_body_limit_is_enforced(self) -> None:
        fetcher = SafeFetcher(FetchPolicy(max_response_bytes=4))
        fake_response = Mock(status=200)
        fake_response.read.return_value = b"12345"
        fake_response.getheaders.return_value = []
        connection = Mock()
        connection.getresponse.return_value = fake_response
        with patch("safe_egress.client._PinnedHTTPConnection", return_value=connection):
            with self.assertRaises(ResponseTooLargeError):
                fetcher._send(SafeFetcher._parse_target("http://example.test/"), PUBLIC_IP, {})
        connection.close.assert_called_once()

    def test_gzip_response_is_decoded_with_a_bounded_output(self) -> None:
        fetcher = SafeFetcher(FetchPolicy(max_response_bytes=1024))
        compressed = gzip.compress(b"public fixture content")
        fake_response = Mock(status=200)
        fake_response.read.return_value = compressed
        fake_response.getheaders.return_value = [
            ("Content-Encoding", "gzip"),
            ("Content-Length", str(len(compressed))),
            ("Content-Type", "text/plain"),
        ]
        connection = Mock()
        connection.getresponse.return_value = fake_response

        with patch("safe_egress.client._PinnedHTTPConnection", return_value=connection):
            result = fetcher._send(SafeFetcher._parse_target("http://public.example/"), PUBLIC_IP, {})

        self.assertEqual(result.content, b"public fixture content")
        self.assertNotIn("Content-Encoding", {name for name, _value in result.headers})
        self.assertIn(("Content-Length", str(len(result.content))), result.headers)

    def test_gzip_expansion_cannot_exceed_response_body_limit(self) -> None:
        fetcher = SafeFetcher(FetchPolicy(max_response_bytes=1024))
        compressed = gzip.compress(b"A" * 100_000)
        self.assertLess(len(compressed), 1024)
        fake_response = Mock(status=200)
        fake_response.read.return_value = compressed
        fake_response.getheaders.return_value = [("Content-Encoding", "gzip")]
        connection = Mock()
        connection.getresponse.return_value = fake_response

        with patch("safe_egress.client._PinnedHTTPConnection", return_value=connection):
            with self.assertRaises(ResponseTooLargeError):
                fetcher._send(SafeFetcher._parse_target("http://public.example/"), PUBLIC_IP, {})
        connection.close.assert_called_once()

    def test_compressed_content_codings_cover_members_and_exact_limit(self) -> None:
        from safe_egress.client import _decode_response_body

        exact_body = b"x" * 1024
        decoded, _headers = _decode_response_body(
            gzip.compress(exact_body), (("Content-Encoding", "gzip"),), len(exact_body)
        )
        self.assertEqual(decoded, exact_body)

        concatenated_gzip = gzip.compress(b"first") + gzip.compress(b"second")
        decoded, _headers = _decode_response_body(
            concatenated_gzip, (("Content-Encoding", "gzip"),), 11
        )
        self.assertEqual(decoded, b"firstsecond")

        wrapped_deflate = zlib.compress(b"wrapped deflate")
        decoded, _headers = _decode_response_body(
            wrapped_deflate, (("Content-Encoding", "deflate"),), 32
        )
        self.assertEqual(decoded, b"wrapped deflate")

        raw_deflater = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        raw_deflate = raw_deflater.compress(b"raw deflate") + raw_deflater.flush()
        decoded, _headers = _decode_response_body(
            raw_deflate, (("Content-Encoding", "deflate"),), 32
        )
        self.assertEqual(decoded, b"raw deflate")

        stacked = zlib.compress(gzip.compress(b"stacked coding"))
        decoded, _headers = _decode_response_body(
            stacked, (("Content-Encoding", "gzip, deflate"),), 64
        )
        self.assertEqual(decoded, b"stacked coding")

    def test_headers_cannot_override_host_or_proxy_routing(self) -> None:
        for headers in ({"Host": "127.0.0.1"}, {"Proxy-Authorization": "dummy"}, {"X-Test": "bad\r\nvalue"}):
            with self.subTest(headers=headers), self.assertRaises(PolicyError):
                SafeFetcher._prepare_headers(headers)

    def test_pinned_connections_use_a_numeric_socket_address(self) -> None:
        connection = _PinnedHTTPConnection("example.test", 80, PUBLIC_IP, 2.0)
        fake_socket = Mock()
        with patch("safe_egress.client.socket.socket", return_value=fake_socket) as socket_factory:
            self.assertIs(connection._create_connection(("example.test", 80)), fake_socket)
        socket_factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        fake_socket.connect.assert_called_once_with(("93.184.216.34", 80))

    def test_https_connection_keeps_original_hostname_for_tls(self) -> None:
        connection = _PinnedHTTPSConnection(
            "service.example", 443, PUBLIC_IP, 2.0, SafeFetcher()._ssl_context
        )
        self.assertEqual(connection.host, "service.example")
        self.assertIs(connection._create_connection.__self__, connection)


if __name__ == "__main__":
    unittest.main()
