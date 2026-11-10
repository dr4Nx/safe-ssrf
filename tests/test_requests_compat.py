from __future__ import annotations

import importlib.util
import ipaddress
import socket
import unittest
from unittest.mock import patch

from safe_egress import FetchPolicy, FetchResponse, PolicyError, SafeFetcher

if importlib.util.find_spec("requests") is not None:
    import requests
    from safe_egress.adapters import requests as requests_compat
else:  # pragma: no cover - optional dependency
    requests = None
    requests_compat = None


@unittest.skipIf(requests is None, "install safe-egress[requests] to run Requests compatibility tests")
class RequestsCompatibilityTests(unittest.TestCase):
    def test_allow_builds_exact_host_and_ip_policy(self) -> None:
        policy = requests_compat.Allow("10.20.30.40", "API.Example.")

        self.assertIsInstance(policy, FetchPolicy)
        self.assertEqual(policy.allowed_hosts, frozenset({"10.20.30.40", "api.example"}))
        self.assertEqual(policy.allowed_ips, frozenset({ipaddress.ip_address("10.20.30.40")}))
        self.assertTrue(policy.permits_address(ipaddress.ip_address("10.20.30.40")))
        self.assertFalse(policy.permits_address(ipaddress.ip_address("10.20.30.41")))
        self.assertEqual(policy.check_host("Api.Example."), "api.example")
        with self.assertRaises(PolicyError):
            policy.check_host("unlisted.example")

    def test_allow_rejects_urls_wildcards_and_non_string_destinations(self) -> None:
        for destination in ("https://api.example", "*.example", "10.0.0.0/8"):
            with self.subTest(destination=destination), self.assertRaises(PolicyError):
                requests_compat.Allow(destination)
        with self.assertRaises(ValueError):
            requests_compat.Allow(123)  # type: ignore[arg-type]

    def test_allow_policy_preserves_public_get_and_rechecks_redirects(self) -> None:
        public_ip = ipaddress.ip_address("93.184.216.34")
        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (str(public_ip), 80))]
        sent: list[str] = []

        def simulated_send(fetcher, target, address, headers, **kwargs):
            del fetcher, headers
            self.assertEqual(address, public_ip)
            sent.append(target.url)
            if target.url.endswith("/redirect"):
                return FetchResponse(
                    302,
                    (("Location", "http://unlisted.example/internal"),),
                    b"",
                    target.url,
                    (),
                    kwargs["method"],
                )
            return FetchResponse(
                200,
                (("Content-Type", "text/plain"),),
                b"PUBLIC_FIXTURE_CONTENT",
                target.url,
                (),
                kwargs["method"],
            )

        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            SafeFetcher, "_send", new=simulated_send
        ):
            response = requests_compat.get(
                "http://api.example/document",
                policy=requests_compat.Allow("api.example"),
            )
            self.assertEqual(response.content, b"PUBLIC_FIXTURE_CONTENT")

            with self.assertRaises(requests.exceptions.ConnectionError):
                requests_compat.get(
                    "http://api.example/redirect",
                    policy=requests_compat.Allow("api.example"),
                )

        self.assertEqual(
            sent,
            ["http://api.example/document", "http://api.example/redirect"],
        )

    def test_top_level_exception_aliases_match_requests(self) -> None:
        for name in (
            "ConnectTimeout",
            "ConnectionError",
            "FileModeWarning",
            "HTTPError",
            "JSONDecodeError",
            "ReadTimeout",
            "RequestException",
            "Timeout",
            "TooManyRedirects",
            "URLRequired",
        ):
            with self.subTest(name=name):
                self.assertIs(getattr(requests_compat, name), getattr(requests, name))

    def test_module_level_get_keeps_common_requests_behavior(self) -> None:
        public_ip = ipaddress.ip_address("93.184.216.34")
        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (str(public_ip), 80))]
        checked: list[tuple[str, str]] = []

        def simulated_send(fetcher, target, address, headers, **kwargs):
            del fetcher, headers
            self.assertEqual(address, public_ip)
            checked.append((kwargs["method"], target.url))
            return FetchResponse(
                200,
                (("Content-Type", "text/plain; charset=utf-8"),),
                b"PUBLIC_FIXTURE_CONTENT",
                target.url,
                (),
                kwargs["method"],
            )

        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            SafeFetcher, "_send", new=simulated_send
        ):
            response = requests_compat.get(
                "http://public.example/research", params={"q": "ssrf test"}
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "PUBLIC_FIXTURE_CONTENT")
        self.assertEqual(response.url, "http://public.example/research?q=ssrf+test")
        self.assertEqual(checked, [("GET", response.url)])

    def test_session_alias_uses_safe_session_and_private_default_fails_closed(self) -> None:
        self.assertIs(requests_compat.Session, requests_compat.SafeRequestsSession)
        self.assertIs(requests_compat.PreparedRequest, requests.PreparedRequest)
        created_session = requests_compat.session()
        self.assertIsInstance(created_session, requests_compat.Session)
        created_session.close()
        with patch.object(SafeFetcher, "_send") as send:
            with requests_compat.Session() as session:
                with self.assertRaises(requests.exceptions.ConnectionError):
                    session.get("http://127.0.0.1/internal-status")
        send.assert_not_called()

    def test_module_level_request_accepts_explicit_policy_and_rejects_proxy(self) -> None:
        local_ip = ipaddress.ip_address("127.0.0.1")
        policy = FetchPolicy(
            allowed_ips=frozenset({"127.0.0.1"}),
            allowed_ports=frozenset({80}),
        )

        def simulated_send(fetcher, target, address, headers, **kwargs):
            del fetcher, headers
            self.assertEqual(address, local_ip)
            return FetchResponse(200, (), b"CONTROLLED_LOCAL_FIXTURE", target.url, (), kwargs["method"])

        with patch.object(SafeFetcher, "_send", new=simulated_send):
            response = requests_compat.get("http://127.0.0.1/status", policy=policy)
        self.assertEqual(response.content, b"CONTROLLED_LOCAL_FIXTURE")

        with self.assertRaises(PolicyError):
            requests_compat.get("http://public.example/", proxies={"http": "http://proxy.invalid"})


if __name__ == "__main__":
    unittest.main()
