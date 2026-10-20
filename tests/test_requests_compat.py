from __future__ import annotations

import importlib.util
import ipaddress
import socket
import unittest
from unittest.mock import patch

from safe_egress import FetchPolicy, FetchResponse, PolicyError, SafeFetcher

if importlib.util.find_spec("requests") is not None:
    import requests
    from safe_egress import requests_compat
else:  # pragma: no cover - optional dependency
    requests = None
    requests_compat = None


@unittest.skipIf(requests is None, "install safe-egress[requests] to run Requests compatibility tests")
class RequestsCompatibilityTests(unittest.TestCase):
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
        with patch.object(SafeFetcher, "_send") as send:
            with requests_compat.Session() as session:
                with self.assertRaises(requests.exceptions.ConnectionError):
                    session.get("http://127.0.0.1/internal-status")
        send.assert_not_called()

    def test_module_level_request_accepts_explicit_policy_and_rejects_proxy(self) -> None:
        local_ip = ipaddress.ip_address("127.0.0.1")
        policy = FetchPolicy(
            allowed_private_hosts=frozenset({"127.0.0.1"}),
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
