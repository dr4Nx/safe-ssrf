from __future__ import annotations

import gzip
import ipaddress
import socket
import unittest
import zlib
from unittest.mock import Mock, patch

from safe_egress import (
    FetchError,
    FetchPolicy,
    FetchResponse,
    PolicyError,
    RedirectLimitError,
    RequestTooLargeError,
    ResponseTooLargeError,
    SafeFetcher,
    ValidatedDestination,
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

    def test_noncanonical_numeric_ipv4_forms_are_rejected_before_dns(self) -> None:
        fetcher = SafeFetcher()
        urls = (
            "http://127.1/",
            "http://0177.0.0.1/",
            "http://0x7f000001/",
            "http://0x7f.0x0.0x0.0x1/",
            "http://2130706433/",
        )
        with patch("safe_egress.client.socket.getaddrinfo") as resolve:
            for url in urls:
                with self.subTest(url=url), self.assertRaises(PolicyError):
                    fetcher.validate_destination(url)
        resolve.assert_not_called()

    def test_canonical_public_ipv4_literal_remains_usable_without_dns(self) -> None:
        fetcher = SafeFetcher()
        with patch("safe_egress.client.socket.getaddrinfo") as resolve:
            target = fetcher.validate_destination("http://93.184.216.34/")
        self.assertEqual(target.addresses, (PUBLIC_IP,))
        resolve.assert_not_called()

    def test_multicast_literals_are_rejected_before_resolution_or_send(self) -> None:
        fetcher = SafeFetcher()
        with patch("safe_egress.client.socket.getaddrinfo") as resolve, patch.object(
            fetcher, "_send"
        ) as send:
            for url in ("http://224.0.0.1/", "http://[ff02::1]/"):
                with self.subTest(url=url), self.assertRaises(PolicyError):
                    fetcher.validate_destination(url)
        resolve.assert_not_called()
        send.assert_not_called()

    def test_iana_globally_reachable_special_ip_is_accepted_without_dns(self) -> None:
        fetcher = SafeFetcher()
        with patch("safe_egress.client.socket.getaddrinfo") as resolve:
            target = fetcher.validate_destination("https://[2001:1::3]/")
        self.assertEqual(target.addresses, (ipaddress.ip_address("2001:1::3"),))
        resolve.assert_not_called()

    def test_iana_non_global_special_literals_are_rejected_before_send(self) -> None:
        fetcher = SafeFetcher()
        with patch.object(fetcher, "_send") as send:
            for url in (
                "http://192.88.99.1/",
                "http://[100:0:0:1::1]/",
                "http://[5f00::1]/",
                "http://[64:ff9b:1::7f00:1]/",
            ):
                with self.subTest(url=url), self.assertRaises(PolicyError):
                    fetcher.get(url)
        send.assert_not_called()

    def test_exact_private_ip_exception_can_fetch_simulated_service(self) -> None:
        service = SimulatedService()
        policy = FetchPolicy(
            allowed_hosts=frozenset({"fixture.internal"}),
            allowed_ips=frozenset({"127.0.0.1"}),
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

    def test_ip_exception_still_obeys_exact_host_allowlist(self) -> None:
        policy = FetchPolicy(
            allowed_hosts=frozenset({"trusted.internal"}),
            allowed_ips=frozenset({"127.0.0.1"}),
        )
        fetcher = SafeFetcher(policy)
        transport = Mock()
        with patch("safe_egress.client.socket.getaddrinfo", return_value=resolver_records("127.0.0.1")), patch.object(
            fetcher, "_send", transport
        ):
            with self.assertRaises(PolicyError):
                fetcher.get("http://other.internal/")
        transport.assert_not_called()

    def test_exact_ip_exception_does_not_allow_other_private_dns_answers(self) -> None:
        policy = FetchPolicy(
            allowed_hosts=frozenset({"trusted.internal"}),
            allowed_ips=frozenset({"127.0.0.1"}),
        )
        records = resolver_records("127.0.0.1", "169.254.169.254")
        with patch("safe_egress.client.socket.getaddrinfo", return_value=records):
            with self.assertRaises(PolicyError):
                SafeFetcher(policy)._resolve_and_check("trusted.internal", 80)

    def test_exact_ip_exception_allows_known_peer_but_rejects_dns_rebinding(self) -> None:
        service = SimulatedService()
        known_peer = ipaddress.ip_address("10.20.0.5")
        rebound_peer = ipaddress.ip_address("10.20.0.6")
        policy = FetchPolicy(
            allowed_hosts=frozenset({"files.internal.example"}),
            allowed_ips=frozenset({str(known_peer)}),
        )
        fetcher = SafeFetcher(policy)
        resolver = Mock(
            side_effect=(
                resolver_records(str(known_peer)),
                resolver_records(str(rebound_peer)),
            )
        )
        with patch("safe_egress.client.socket.getaddrinfo", resolver), patch.object(
            fetcher, "_send", side_effect=service.send
        ):
            first = fetcher.get("http://files.internal.example/document")
            with self.assertRaises(PolicyError):
                fetcher.get("http://files.internal.example/document")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(service.requests[0][1], known_peer)
        self.assertEqual(len(service.requests), 1)

    def test_exact_ip_exception_rejects_mixed_authorized_and_metadata_answers(self) -> None:
        known_peer = ipaddress.ip_address("10.20.0.5")
        records = resolver_records(str(known_peer), "169.254.169.254")
        policy = FetchPolicy(allowed_ips=frozenset({str(known_peer)}))
        with patch("safe_egress.client.socket.getaddrinfo", return_value=records):
            with self.assertRaises(PolicyError):
                SafeFetcher(policy)._resolve_and_check("files.internal.example", 80)

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
        self.assertEqual(result.peer_ip, str(PUBLIC_IP))
        self.assertIn(("Content-Type", "text/html"), result.headers)
        self.assertEqual(service.requests[0][1], PUBLIC_IP)
        self.assertEqual(service.requests[0][0].request_target, "/resource?q=1")

    def test_validate_destination_exposes_all_checked_addresses_without_connecting(self) -> None:
        addresses = (PUBLIC_IP, ipaddress.ip_address("1.1.1.1"))
        fetcher = SafeFetcher()
        with patch(
            "safe_egress.client.socket.getaddrinfo",
            return_value=resolver_records(*(str(address) for address in addresses)),
        ), patch.object(fetcher, "_send") as send:
            target = fetcher.validate_destination("https://PUBLIC.example./a?q=1")

        self.assertEqual(target.scheme, "https")
        self.assertEqual(target.host, "public.example")
        self.assertEqual(target.port, 443)
        self.assertEqual(target.request_target, "/a?q=1")
        self.assertEqual(target.addresses, addresses)
        self.assertEqual(target.origin, ("https", "public.example", 443))
        self.assertIsInstance(target, ValidatedDestination)
        send.assert_not_called()

    def test_validate_destination_applies_per_call_private_ip_exception(self) -> None:
        private_ip = ipaddress.ip_address("10.20.0.5")
        fetcher = SafeFetcher()
        policy = FetchPolicy(
            allowed_hosts=frozenset({"files.internal.example"}),
            allowed_ips=frozenset({private_ip}),
        )
        with patch(
            "safe_egress.client.socket.getaddrinfo",
            return_value=resolver_records(str(private_ip)),
        ):
            target = fetcher.validate_destination(
                "https://files.internal.example/document",
                policy=policy,
            )

        self.assertEqual(target.addresses, (private_ip,))

    def test_validate_destination_rejects_mixed_public_and_private_answers(self) -> None:
        fetcher = SafeFetcher()
        with patch(
            "safe_egress.client.socket.getaddrinfo",
            return_value=resolver_records(str(PUBLIC_IP), "169.254.169.254"),
        ):
            with self.assertRaises(PolicyError):
                fetcher.validate_destination("http://public.example/")

    def test_validated_dns_address_is_pinned_through_the_request(self) -> None:
        fetcher = SafeFetcher()
        resolver = Mock(
            side_effect=(resolver_records(str(PUBLIC_IP)), resolver_records("127.0.0.1"))
        )
        fake_response = Mock(status=200)
        fake_response.read.return_value = b"PUBLIC_FIXTURE_CONTENT"
        fake_response.getheaders.return_value = [("Content-Type", "text/plain")]
        connection = Mock()
        connection.getresponse.return_value = fake_response

        with patch("safe_egress.client.socket.getaddrinfo", resolver), patch(
            "safe_egress.client._PinnedHTTPConnection", return_value=connection
        ) as pinned_connection:
            result = fetcher.get("http://rebind.example/resource")

        resolver.assert_called_once_with("rebind.example", 80, type=socket.SOCK_STREAM)
        pinned_connection.assert_called_once_with(
            "rebind.example", 80, PUBLIC_IP, fetcher.policy.timeout_seconds
        )
        connection.request.assert_called_once()
        self.assertEqual(result.peer_ip, str(PUBLIC_IP))
        self.assertEqual(result.content, b"PUBLIC_FIXTURE_CONTENT")

    def test_connection_failure_falls_back_to_another_validated_address(self) -> None:
        fetcher = SafeFetcher()
        first_ip = ipaddress.ip_address("2606:4700:4700::1111")
        second_ip = ipaddress.ip_address("93.184.216.34")
        records = resolver_records(str(first_ip), str(second_ip))

        first_connection = Mock()
        first_connection.connect.side_effect = OSError("synthetic connect failure")
        second_connection = Mock()
        fake_response = Mock(status=200)
        fake_response.read.return_value = b"PUBLIC_FIXTURE_CONTENT"
        fake_response.getheaders.return_value = [("Content-Type", "text/plain")]
        second_connection.getresponse.return_value = fake_response

        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch(
            "safe_egress.client._PinnedHTTPConnection",
            side_effect=(first_connection, second_connection),
        ):
            result = fetcher.get("http://public.example/resource")

        first_connection.request.assert_not_called()
        second_connection.connect.assert_called_once()
        second_connection.request.assert_called_once()
        second_connection.sock.settimeout.assert_called_once_with(fetcher.policy.timeout_seconds)
        self.assertEqual(second_connection.timeout, fetcher.policy.timeout_seconds)
        self.assertEqual(result.content, b"PUBLIC_FIXTURE_CONTENT")
        self.assertEqual(result.peer_ip, str(second_ip))

    def test_address_fallback_shares_one_connection_timeout_budget(self) -> None:
        fetcher = SafeFetcher(FetchPolicy(timeout_seconds=5.0))
        records = resolver_records(
            "2606:4700:4700::1111",
            "2606:4700:4700::1112",
            "93.184.216.34",
        )
        first_connection = Mock()
        first_connection.connect.side_effect = OSError("synthetic connect failure")
        second_connection = Mock()
        observed_second_timeout: list[float] = []

        def fail_second_connect() -> None:
            observed_second_timeout.append(second_connection.timeout)
            raise OSError("synthetic connect failure")

        second_connection.connect.side_effect = fail_second_connect
        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch(
            "safe_egress.client._PinnedHTTPConnection",
            side_effect=(first_connection, second_connection),
        ) as connection_factory, patch(
            "safe_egress.client.time.monotonic", side_effect=(0.0, 0.0, 1.0, 5.0)
        ):
            with self.assertRaises(FetchError):
                fetcher.get("http://public.example/resource")

        self.assertEqual(connection_factory.call_count, 2)
        self.assertEqual(observed_second_timeout, [4.0])

    def test_request_failure_does_not_retry_on_another_address(self) -> None:
        fetcher = SafeFetcher()
        records = resolver_records("2606:4700:4700::1111", str(PUBLIC_IP))
        connection = Mock()
        connection.request.side_effect = OSError("synthetic write failure")

        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch(
            "safe_egress.client._PinnedHTTPConnection", return_value=connection
        ) as connection_factory:
            with self.assertRaises(FetchError):
                fetcher.get("http://public.example/resource")

        connection.connect.assert_called_once()
        connection.request.assert_called_once()
        connection_factory.assert_called_once()

    def test_pinned_connection_connects_to_numeric_ipv4_and_ipv6_without_dns(self) -> None:
        cases = (
            (ipaddress.ip_address("93.184.216.34"), socket.AF_INET, ("93.184.216.34", 8080)),
            (ipaddress.ip_address("2606:4700:4700::1111"), socket.AF_INET6,
             ("2606:4700:4700::1111", 8443, 0, 0)),
        )
        for pinned_ip, expected_family, expected_sockaddr in cases:
            with self.subTest(pinned_ip=pinned_ip):
                connection = object.__new__(_PinnedHTTPConnection)
                connection._safe_egress_ip = pinned_ip
                with patch("safe_egress.client.socket.socket") as socket_factory, patch(
                    "safe_egress.client.socket.getaddrinfo"
                ) as resolve:
                    sock = socket_factory.return_value
                    returned = connection._create_pinned_connection(
                        ("untrusted.example", expected_sockaddr[1]), timeout=2
                    )

                self.assertIs(returned, sock)
                socket_factory.assert_called_once_with(expected_family, socket.SOCK_STREAM)
                sock.settimeout.assert_called_once_with(2)
                sock.connect.assert_called_once_with(expected_sockaddr)
                resolve.assert_not_called()

    def test_pinned_https_connects_to_numeric_ip_but_keeps_tls_hostname(self) -> None:
        pinned_ip = ipaddress.ip_address("93.184.216.34")
        raw_socket = Mock()
        tls_socket = Mock()
        tls_context = Mock()
        tls_context.wrap_socket.return_value = tls_socket
        connection = _PinnedHTTPSConnection(
            "tls-public.example", 443, pinned_ip, 2, tls_context
        )

        with patch("safe_egress.client.socket.socket", return_value=raw_socket) as socket_factory, patch(
            "safe_egress.client.socket.getaddrinfo"
        ) as resolve:
            connection.connect()

        socket_factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        raw_socket.connect.assert_called_once_with(("93.184.216.34", 443))
        tls_context.wrap_socket.assert_called_once_with(
            raw_socket, server_hostname="tls-public.example"
        )
        self.assertIs(connection.sock, tls_socket)
        resolve.assert_not_called()

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
        fetcher = SafeFetcher(
            FetchPolicy(
                allowed_hosts=frozenset({"start.internal"}),
                allowed_ips=frozenset({"127.0.0.1"}),
            )
        )
        with patch("safe_egress.client.socket.getaddrinfo", return_value=resolver_records("127.0.0.1")), patch.object(
            fetcher, "_send", side_effect=first.send
        ):
            with self.assertRaises(PolicyError):
                fetcher.get("http://start.internal/start")
        self.assertEqual(len(first.requests), 1)

    def test_scheme_relative_redirect_to_loopback_is_rejected_before_second_request(self) -> None:
        first = SimulatedService(status=302, headers=(("Location", "//127.0.0.1/internal"),))
        fetcher = SafeFetcher()
        resolver = Mock(return_value=resolver_records(str(PUBLIC_IP)))
        with patch("safe_egress.client.socket.getaddrinfo", resolver), patch.object(
            fetcher, "_send", side_effect=first.send
        ) as send:
            with self.assertRaises(PolicyError):
                fetcher.get("http://public.example/start")

        resolver.assert_called_once_with("public.example", 80, type=socket.SOCK_STREAM)
        self.assertEqual(len(first.requests), 1)
        send.assert_called_once()

    def test_redirects_are_revalidated_and_cross_origin_credentials_removed(self) -> None:
        source = SimulatedService(status=302, headers=(("Location", "http://second.internal/end"),))
        destination = SimulatedService(body=b"destination response")
        allowed = {"first.internal", "second.internal"}
        policy = FetchPolicy(
            allowed_hosts=frozenset(allowed),
            allowed_ips=frozenset({"127.0.0.1"}),
            additional_sensitive_headers=frozenset({"X-Company-Secret"}),
        )
        fetcher = SafeFetcher(policy)

        def send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            return (source if target.host == "first.internal" else destination).send(target, address, headers)

        with patch("safe_egress.client.socket.getaddrinfo", return_value=resolver_records("127.0.0.1")), patch.object(
            fetcher, "_send", side_effect=send
        ):
            result = fetcher.get(
                "http://first.internal/start",
                headers={
                    "Authorization": "Bearer dummy",
                    "Cookie": "session=dummy",
                    "Origin": "http://first.internal",
                    "Referer": "http://first.internal/page?token=dummy",
                    "X-API-Key": "dummy-api-key",
                    "X-Aws-Ec2-Metadata-Token": "dummy-imdsv2-token",
                    "X-Vault-Token": "dummy-vault-token",
                    "X-Company-Secret": "dummy-custom-secret",
                },
            )

        self.assertEqual(result.content, b"destination response")
        self.assertEqual(result.history, ("http://first.internal/start",))
        self.assertIn("Authorization", source.requests[0][2])
        for sensitive in (
            "authorization",
            "cookie",
            "origin",
            "referer",
            "x-api-key",
            "x-aws-ec2-metadata-token",
            "x-vault-token",
            "x-company-secret",
        ):
            self.assertNotIn(sensitive, {key.lower() for key in destination.requests[0][2]})

    def test_peer_ip_reports_the_final_redirect_connection(self) -> None:
        first_ip = ipaddress.ip_address("93.184.216.34")
        final_ip = ipaddress.ip_address("1.1.1.1")
        source = SimulatedService(status=302, headers=(("Location", "https://second.example/final"),))
        destination = SimulatedService(body=b"final public response")
        fetcher = SafeFetcher(FetchPolicy(allowed_hosts=frozenset({"first.example", "second.example"})))

        def resolve(host, port, *, type):
            del port, type
            address = first_ip if host == "first.example" else final_ip
            return resolver_records(str(address))

        def send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            service = source if target.host == "first.example" else destination
            return service.send(target, address, headers, method=method, body=body, timeout_seconds=timeout_seconds)

        with patch("safe_egress.client.socket.getaddrinfo", side_effect=resolve), patch.object(
            fetcher, "_send", side_effect=send
        ):
            result = fetcher.get("https://first.example/start")

        self.assertEqual(result.content, b"final public response")
        self.assertEqual(source.requests[0][1], first_ip)
        self.assertEqual(destination.requests[0][1], final_ip)
        self.assertEqual(result.peer_ip, str(final_ip))

    def test_same_origin_redirect_preserves_caller_headers(self) -> None:
        source = SimulatedService(status=302, headers=(("Location", "/next"),))
        destination = SimulatedService(body=b"done")
        fetcher = SafeFetcher(
            FetchPolicy(
                allowed_hosts=frozenset({"same.internal"}),
                allowed_ips=frozenset({"127.0.0.1"}),
            )
        )

        def send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            return (source if target.request_target == "/start" else destination).send(target, address, headers)

        with patch("safe_egress.client.socket.getaddrinfo", return_value=resolver_records("127.0.0.1")), patch.object(
            fetcher, "_send", side_effect=send
        ):
            fetcher.get(
                "http://same.internal/start",
                headers={
                    "Authorization": "Bearer dummy",
                    "Cookie": "dummy",
                    "Referer": "http://same.internal/page?token=dummy",
                    "X-API-Key": "dummy-api-key",
                },
            )
        self.assertEqual(destination.requests[0][2]["Authorization"], "Bearer dummy")
        self.assertEqual(destination.requests[0][2]["Cookie"], "dummy")
        self.assertEqual(
            destination.requests[0][2]["Referer"],
            "http://same.internal/page?token=dummy",
        )
        self.assertEqual(destination.requests[0][2]["X-API-Key"], "dummy-api-key")

    def test_redirect_limit_is_enforced(self) -> None:
        loop = SimulatedService(status=302, headers=(("Location", "/again"),))
        fetcher = SafeFetcher(
            FetchPolicy(
                allowed_hosts=frozenset({"loop.internal"}),
                allowed_ips=frozenset({"127.0.0.1"}),
                max_redirects=1,
            )
        )
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
