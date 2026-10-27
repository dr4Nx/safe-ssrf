from __future__ import annotations

import ipaddress
import socket
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from safe_egress import (
    FetchError,
    FetchPolicy,
    PolicyError,
    RedirectLimitError,
    ResponseTooLargeError,
    SafeCurlCffiSession,
    SafeFetcher,
    ValidatedDestination,
)
from safe_egress import curl_cffi_adapter


class _FakeResponse:
    def __init__(
        self,
        *,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        content: bytes = b"PUBLIC FIXTURE",
        primary_ip: str = "93.184.216.34",
        primary_port: int = 443,
    ) -> None:
        self.status_code = status_code
        self.headers = headers or {}
        self.content = content
        self.primary_ip = primary_ip
        self.primary_port = primary_port
        self.url = ""
        self.history = []


class _FakeCurlFfi:
    @staticmethod
    def callback(_signature):
        return lambda function: function

    @staticmethod
    def cast(_target_type, value):
        return value

    @staticmethod
    def string(value):
        return value if isinstance(value, bytes) else str(value).encode("ascii")

    @staticmethod
    def buffer(value, size):
        return memoryview(value)[:size]


class _FakeCurl:
    def __init__(self, **_kwargs) -> None:
        self._curl = self
        self.options = {}

    def setopt(self, option, value):
        self.options[option] = value
        return 0

    def _check_error(self, result, *_args):
        if result:
            raise RuntimeError("fake curl setopt failed")


class _FakeCurlLib:
    @staticmethod
    def _curl_easy_setopt(handle, option, value):
        handle.options[option] = value
        return 0


_FakeCurlModule = SimpleNamespace(
    Curl=_FakeCurl,
    ffi=_FakeCurlFfi,
    lib=_FakeCurlLib,
)


class _FakeCurlRequests:
    instances: list[_FakeCurlRequests._Session] = []
    responses: list[_FakeResponse] = []
    socket_open_outcomes: list[tuple[int, bool]] = []
    write_error = 0xFFFFFFFF

    class _Session:
        def __init__(self, **kwargs) -> None:
            self.options = kwargs
            self.curl = kwargs["curl"]
            self.calls: list[dict[str, object]] = []
            self.body_callback_calls = 0
            _FakeCurlRequests.instances.append(self)
            for option, value in kwargs["curl_options"].items():
                self.curl.setopt(option, value)

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

        def request(self, method, url, **kwargs):
            call = {"method": method, "url": url, **kwargs}
            self.calls.append(call)
            response = _FakeCurlRequests.responses.pop(0)
            opensocket = self.curl.options[curl_cffi_adapter._CURL_OPENSOCKETFUNCTION]
            address = _fake_curl_sockaddr(response.primary_ip, response.primary_port)
            with patch("safe_egress.curl_cffi_adapter.socket.socket") as socket_factory:
                socket_factory.return_value.detach.return_value = 41
                socket_result = opensocket(None, 0, address)
                _FakeCurlRequests.socket_open_outcomes.append(
                    (socket_result, socket_factory.called)
                )
                if socket_result == -1:
                    raise RuntimeError("curl open-socket callback rejected peer")
            prereq = self.curl.options[20312]
            if prereq(
                None,
                response.primary_ip.encode("ascii"),
                b"127.0.0.1",
                response.primary_port,
                54321,
            ):
                raise RuntimeError("curl prerequest callback rejected peer")
            callback = kwargs["content_callback"]
            self.body_callback_calls += 1
            callback_result = callback(response.content)
            if callback_result == _FakeCurlRequests.write_error:
                raise RuntimeError("curl write callback aborted")
            return response

    Session = _Session


def _records(*ips: str):
    records = []
    for address in ips:
        parsed = ipaddress.ip_address(address)
        family = socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
        records.append((family, socket.SOCK_STREAM, 0, "", (address, 443, 0, 0) if family == socket.AF_INET6 else (address, 443)))
    return records


def _fake_curl_sockaddr(
    address: str,
    port: int,
    *,
    socktype: int = socket.SOCK_STREAM,
    protocol: int = socket.IPPROTO_TCP,
) -> bytes:
    """Build the POSIX curl_sockaddr prefix plus a dummy sockaddr payload."""
    parsed = ipaddress.ip_address(address)
    family = socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
    sockaddr = bytearray(28 if family == socket.AF_INET6 else 16)
    sockaddr[2:4] = port.to_bytes(2, "big")
    if family == socket.AF_INET6:
        sockaddr[8:24] = parsed.packed
    else:
        sockaddr[4:8] = parsed.packed
    prefix = b"".join(
        value.to_bytes(4, byteorder=sys.byteorder, signed=True)
        for value in (family, socktype, protocol)
    ) + len(sockaddr).to_bytes(4, byteorder=sys.byteorder)
    return prefix + sockaddr


class SafeCurlCffiSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        _FakeCurlRequests.instances = []
        _FakeCurlRequests.responses = []
        _FakeCurlRequests.socket_open_outcomes = []
        self.loader = patch.object(
            curl_cffi_adapter,
            "_load_curl_cffi",
            return_value=(
                _FakeCurlRequests,
                SimpleNamespace(RESOLVE=10001, PREREQFUNCTION=20312),
                _FakeCurlModule,
                _FakeCurlRequests.write_error,
            ),
        )
        self.loader.start()
        self.addCleanup(self.loader.stop)

    def test_private_curl_bridge_is_limited_to_the_reviewed_version(self) -> None:
        curl_cffi_adapter._require_curl_cffi_version("0.15.0")
        with self.assertRaisesRegex(ImportError, "supports curl-cffi==0.15.0"):
            curl_cffi_adapter._require_curl_cffi_version("0.16.0")

    def test_public_fetch_is_pinned_and_preserves_response_body(self) -> None:
        fetcher = SafeFetcher()
        response = _FakeResponse()
        _FakeCurlRequests.responses = [response]
        with patch("safe_egress.client.socket.getaddrinfo", return_value=_records("93.184.216.34")):
            result = SafeCurlCffiSession(fetcher=fetcher).get("https://Public.Example./page")

        self.assertEqual(result.content, b"PUBLIC FIXTURE")
        self.assertEqual(result.url, "https://public.example:443/page")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(len(_FakeCurlRequests.instances), 1)
        session = _FakeCurlRequests.instances[0]
        self.assertIsInstance(session.options["curl"], _FakeCurl)
        self.assertFalse(session.options["use_thread_local_curl"])
        self.assertFalse(session.options["trust_env"])
        self.assertFalse(session.options["allow_redirects"])
        self.assertEqual(session.options["proxies"], {})
        self.assertEqual(
            session.options["curl_options"][10001],
            ["public.example:443:93.184.216.34"],
        )
        self.assertIn(20312, session.options["curl_options"])
        self.assertIn(20312, session.curl.options)
        self.assertIn(curl_cffi_adapter._CURL_OPENSOCKETFUNCTION, session.curl.options)
        self.assertEqual(_FakeCurlRequests.socket_open_outcomes, [(41, True)])
        call = session.calls[0]
        self.assertEqual(call["accept_encoding"], "identity")
        self.assertFalse(call["allow_redirects"])

    def test_all_checked_public_addresses_are_in_the_resolve_rule(self) -> None:
        _FakeCurlRequests.responses = [_FakeResponse()]
        records = _records("93.184.216.34", "1.1.1.1")
        with patch("safe_egress.client.socket.getaddrinfo", return_value=records):
            SafeCurlCffiSession().get("https://public.example/page")

        rule = _FakeCurlRequests.instances[0].options["curl_options"][10001][0]
        self.assertEqual(rule, "public.example:443:93.184.216.34,1.1.1.1")

    def test_mixed_public_private_dns_answers_are_rejected_before_curl(self) -> None:
        records = _records("93.184.216.34", "10.20.30.40")
        with patch("safe_egress.client.socket.getaddrinfo", return_value=records):
            with self.assertRaises(PolicyError):
                SafeCurlCffiSession().get("https://public.example/page")

        self.assertEqual(_FakeCurlRequests.instances, [])

    def test_exact_private_allowlist_is_pinned_with_public_dns_answers(self) -> None:
        policy = FetchPolicy(
            allowed_hosts=frozenset({"public.example"}),
            allowed_ips=frozenset({"10.20.30.40"}),
        )
        records = _records("93.184.216.34", "10.20.30.40")
        _FakeCurlRequests.responses = [_FakeResponse(primary_ip="10.20.30.40")]
        with patch("safe_egress.client.socket.getaddrinfo", return_value=records):
            result = SafeCurlCffiSession(policy).get("https://public.example/private-service")

        self.assertEqual(result.primary_ip, "10.20.30.40")
        rule = _FakeCurlRequests.instances[0].options["curl_options"][10001][0]
        self.assertEqual(rule, "public.example:443:93.184.216.34,10.20.30.40")

    def test_ipv6_dns_answers_use_libcurl_bracket_format(self) -> None:
        destination = ValidatedDestination(
            url="https://public.example/",
            scheme="https",
            host="public.example",
            port=443,
            request_target="/",
            addresses=(ipaddress.ip_address("2606:4700:4700::1111"),),
        )
        self.assertEqual(
            SafeCurlCffiSession._resolve_rule(destination),
            "public.example:443:[2606:4700:4700::1111]",
        )

    def test_opensocket_address_decoder_reads_ipv4_and_ipv6_peers(self) -> None:
        ipv4 = curl_cffi_adapter._decode_curl_socket_address(
            _FakeCurlFfi, _fake_curl_sockaddr("93.184.216.34", 443)
        )
        ipv6 = curl_cffi_adapter._decode_curl_socket_address(
            _FakeCurlFfi, _fake_curl_sockaddr("2606:4700:4700::1111", 8443)
        )

        self.assertEqual(ipv4[0], socket.AF_INET)
        self.assertEqual(ipv4[4:], (ipaddress.ip_address("93.184.216.34"), 443))
        self.assertEqual(ipv6[0], socket.AF_INET6)
        self.assertEqual(
            ipv6[4:], (ipaddress.ip_address("2606:4700:4700::1111"), 8443)
        )

    def test_opensocket_rejects_non_tcp_socket_before_creating_it(self) -> None:
        _FakeCurlRequests.responses = [_FakeResponse()]
        with patch(
            "safe_egress.client.socket.getaddrinfo",
            return_value=_records("93.184.216.34"),
        ):
            SafeCurlCffiSession().get("https://public.example/page")

        callback = _FakeCurlRequests.instances[0].curl.options[
            curl_cffi_adapter._CURL_OPENSOCKETFUNCTION
        ]
        with patch("safe_egress.curl_cffi_adapter.socket.socket") as socket_factory:
            result = callback(
                None,
                0,
                _fake_curl_sockaddr(
                    "93.184.216.34", 443, socktype=socket.SOCK_DGRAM
                ),
            )

        self.assertEqual(result, -1)
        socket_factory.assert_not_called()

    def test_pre_request_peer_guard_accepts_checked_ipv6_peer(self) -> None:
        peer_ip = "2606:4700:4700::1111"
        _FakeCurlRequests.responses = [_FakeResponse(primary_ip=peer_ip)]
        with patch(
            "safe_egress.client.socket.getaddrinfo",
            return_value=_records(peer_ip),
        ):
            result = SafeCurlCffiSession().get("https://public.example/v6")

        self.assertEqual(result.content, b"PUBLIC FIXTURE")
        self.assertEqual(_FakeCurlRequests.instances[0].body_callback_calls, 1)
        self.assertEqual(
            _FakeCurlRequests.instances[0].options["curl_options"][10001],
            ["public.example:443:[2606:4700:4700::1111]"],
        )

    def test_ip_literal_does_not_use_hostname_resolve_override(self) -> None:
        destination = ValidatedDestination(
            url="http://[::1]/",
            scheme="http",
            host="::1",
            port=80,
            request_target="/",
            addresses=(ipaddress.ip_address("::1"),),
        )
        self.assertIsNone(SafeCurlCffiSession._resolve_rule(destination))

    def test_direct_loopback_is_rejected_before_curl_session_creation(self) -> None:
        with self.assertRaises(PolicyError):
            SafeCurlCffiSession().get("http://127.0.0.1:43127/internal")
        self.assertEqual(_FakeCurlRequests.instances, [])

    def test_non_boolean_follow_redirects_is_rejected_before_client_call(self) -> None:
        with self.assertRaises(PolicyError):
            SafeCurlCffiSession().get("https://public.example/", follow_redirects="yes")
        self.assertEqual(_FakeCurlRequests.instances, [])

    def test_public_to_loopback_redirect_is_rejected_before_second_session(self) -> None:
        fetcher = SafeFetcher()
        _FakeCurlRequests.responses = [
            _FakeResponse(
                status_code=302,
                headers={"Location": "http://127.0.0.1:43127/internal"},
                content=b"",
            )
        ]
        with patch("safe_egress.client.socket.getaddrinfo", return_value=_records("93.184.216.34")):
            with self.assertRaises(PolicyError):
                SafeCurlCffiSession(fetcher=fetcher).get("https://public.example/start")

        self.assertEqual(len(_FakeCurlRequests.instances), 1)

    def test_redirect_limit_prevents_an_extra_request(self) -> None:
        policy = FetchPolicy(max_redirects=1)
        _FakeCurlRequests.responses = [
            _FakeResponse(status_code=302, headers={"Location": "/next"}, content=b""),
            _FakeResponse(status_code=302, headers={"Location": "/final"}, content=b""),
        ]
        with patch("safe_egress.client.socket.getaddrinfo", return_value=_records("93.184.216.34")):
            with self.assertRaises(RedirectLimitError):
                SafeCurlCffiSession(policy).get("https://public.example/start")

        self.assertEqual(len(_FakeCurlRequests.instances), 2)

    def test_follow_redirects_false_returns_redirect_response(self) -> None:
        response = _FakeResponse(status_code=302, headers={"Location": "/next"}, content=b"")
        _FakeCurlRequests.responses = [response]
        with patch("safe_egress.client.socket.getaddrinfo", return_value=_records("93.184.216.34")):
            result = SafeCurlCffiSession().get(
                "https://public.example/start",
                follow_redirects=False,
            )

        self.assertIs(result, response)
        self.assertEqual(len(_FakeCurlRequests.instances), 1)

    def test_cross_origin_redirect_strips_sensitive_headers_and_rewrites_post(self) -> None:
        fetcher = SafeFetcher()
        _FakeCurlRequests.responses = [
            _FakeResponse(status_code=302, headers={"Location": "https://other.example/next"}, content=b""),
            _FakeResponse(content=b"PUBLIC FIXTURE", primary_ip="1.1.1.1"),
        ]

        def resolve(host, port, type, proto=0, flags=0):
            address = "93.184.216.34" if host == "public.example" else "1.1.1.1"
            return _records(address)

        with patch("safe_egress.client.socket.getaddrinfo", side_effect=resolve):
            result = SafeCurlCffiSession(fetcher=fetcher).post(
                "https://public.example/start",
                headers={
                    "Authorization": "dummy-secret",
                    "Cookie": "session=dummy",
                    "Content-Type": "application/octet-stream",
                },
                data=b"payload",
            )

        self.assertEqual(result.content, b"PUBLIC FIXTURE")
        self.assertEqual(len(_FakeCurlRequests.instances), 2)
        first = _FakeCurlRequests.instances[0].calls[0]
        second = _FakeCurlRequests.instances[1].calls[0]
        self.assertEqual(first["method"], "POST")
        self.assertEqual(second["method"], "GET")
        self.assertIsNone(second["data"])
        self.assertNotIn("Authorization", second["headers"])
        self.assertNotIn("Cookie", second["headers"])
        self.assertNotIn("Content-Type", second["headers"])
        self.assertEqual(len(result.history), 1)

    def test_response_body_limit_aborts_callback(self) -> None:
        policy = FetchPolicy(max_response_bytes=4)
        _FakeCurlRequests.responses = [_FakeResponse(content=b"too large")]
        with patch("safe_egress.client.socket.getaddrinfo", return_value=_records("93.184.216.34")):
            with self.assertRaises(ResponseTooLargeError):
                SafeCurlCffiSession(policy).get("https://public.example/page")

    def test_unchecked_peer_is_rejected_before_socket_creation(self) -> None:
        _FakeCurlRequests.responses = [_FakeResponse(primary_ip="192.0.2.10")]
        with patch("safe_egress.client.socket.getaddrinfo", return_value=_records("93.184.216.34")):
            with self.assertRaises(FetchError):
                SafeCurlCffiSession().get("https://public.example/page")
        self.assertEqual(_FakeCurlRequests.instances[0].body_callback_calls, 0)
        self.assertEqual(_FakeCurlRequests.socket_open_outcomes, [(-1, False)])

    def test_pre_request_peer_guard_rejects_an_unexpected_port(self) -> None:
        _FakeCurlRequests.responses = [
            _FakeResponse(primary_ip="93.184.216.34", primary_port=8443)
        ]
        with patch(
            "safe_egress.client.socket.getaddrinfo",
            return_value=_records("93.184.216.34"),
        ):
            with self.assertRaises(FetchError):
                SafeCurlCffiSession().get("https://public.example/page")

        self.assertEqual(_FakeCurlRequests.instances[0].body_callback_calls, 0)
        self.assertEqual(_FakeCurlRequests.socket_open_outcomes, [(-1, False)])


if __name__ == "__main__":
    unittest.main()
