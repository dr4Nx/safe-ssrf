from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import ipaddress
import importlib.util
import socket
import threading
import unittest
from unittest.mock import patch

from safe_egress import FetchPolicy, FetchResponse, PolicyError, SafeFetcher

if importlib.util.find_spec("requests") is not None:
    import requests
    from requests.adapters import BaseAdapter
    from safe_egress.requests_adapter import SafeRequestsSession
else:  # pragma: no cover - optional dependency
    requests = None
    BaseAdapter = object
    SafeRequestsSession = None


@unittest.skipIf(requests is None, "install safe-egress[requests] to run Requests adapter tests")
class SafeRequestsSessionTests(unittest.TestCase):
    def test_public_resource_get_uses_hardened_transport(self) -> None:
        fetcher = SafeFetcher()
        public_ip = ipaddress.ip_address("93.184.216.34")
        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (str(public_ip), 443))]

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            self.assertEqual(address, public_ip)
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
            with SafeRequestsSession(fetcher=fetcher) as client:
                response = client.get("https://public.example/resource", timeout=12)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "PUBLIC_FIXTURE_CONTENT")
        self.assertEqual(response.url, "https://public.example/resource")

    def test_per_request_policy_allows_explicit_private_service_without_leaking(self) -> None:
        fetcher = SafeFetcher()
        sent: list[str] = []

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None, policy=None):
            del address, headers, body, timeout_seconds
            self.assertIs(policy, expected_policy)
            sent.append(target.url)
            return FetchResponse(200, (), b"PRIVATE_TEST_FIXTURE", target.url, (), method)

        expected_policy = FetchPolicy(allowed_private_hosts=frozenset({"127.0.0.1"}))
        url = "http://127.0.0.1/internal-status"
        with patch.object(fetcher, "_send", side_effect=simulated_send):
            with SafeRequestsSession(fetcher=fetcher) as client:
                response = client.get(url, policy=expected_policy)
                with self.assertRaises(requests.ConnectionError):
                    client.get(url)

        self.assertEqual(response.content, b"PRIVATE_TEST_FIXTURE")
        self.assertEqual(sent, [url])

    def test_per_request_policy_rechecks_redirect_host_allowlist(self) -> None:
        fetcher = SafeFetcher()
        sent: list[str] = []
        public_ip = ipaddress.ip_address("93.184.216.34")
        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (str(public_ip), 80))]

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None, policy=None):
            del address, headers, body, timeout_seconds
            self.assertIs(policy, expected_policy)
            sent.append(target.url)
            return FetchResponse(
                302,
                (("Location", "http://other-public.example/next"),),
                b"",
                target.url,
                (),
                method,
            )

        expected_policy = FetchPolicy(allowed_hosts=frozenset({"public.example"}))
        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            fetcher, "_send", side_effect=simulated_send
        ):
            with SafeRequestsSession(fetcher=fetcher) as client:
                with self.assertRaises(requests.ConnectionError):
                    client.get("http://public.example/start", policy=expected_policy)

        self.assertEqual(sent, ["http://public.example/start"])

    def test_concurrent_per_request_policies_do_not_cross_between_calls(self) -> None:
        fetcher = SafeFetcher()
        policies = {
            "first": FetchPolicy(allowed_private_hosts=frozenset({"127.0.0.1"}), timeout_seconds=2),
            "second": FetchPolicy(allowed_private_hosts=frozenset({"127.0.0.1"}), timeout_seconds=3),
        }
        barrier = threading.Barrier(2)
        sent: dict[str, FetchPolicy | None] = {}

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None, policy=None):
            del address, headers, body
            barrier.wait(timeout=3)
            sent[target.request_target] = policy
            return FetchResponse(200, (), target.request_target.encode(), target.url, (), method)

        with patch.object(fetcher, "_send", side_effect=simulated_send):
            with SafeRequestsSession(fetcher=fetcher) as client:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    first = pool.submit(client.get, "http://127.0.0.1/first", policy=policies["first"])
                    second = pool.submit(client.get, "http://127.0.0.1/second", policy=policies["second"])
                    first.result(timeout=5)
                    second.result(timeout=5)

        self.assertEqual(sent, {"/first": policies["first"], "/second": policies["second"]})

    def test_per_request_policy_preserves_public_resource_functionality(self) -> None:
        fetcher = SafeFetcher()
        public_ip = ipaddress.ip_address("93.184.216.34")
        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (str(public_ip), 443))]

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None, policy=None):
            del headers, body, timeout_seconds
            self.assertIs(policy, expected_policy)
            self.assertEqual(address, public_ip)
            return FetchResponse(
                200,
                (("Content-Type", "text/plain"),),
                b"PUBLIC_FIXTURE_CONTENT",
                target.url,
                (),
                method,
            )

        expected_policy = FetchPolicy(allowed_hosts=frozenset({"public.example"}))
        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            fetcher, "_send", side_effect=simulated_send
        ):
            with SafeRequestsSession(fetcher=fetcher) as client:
                response = client.request(
                    "GET",
                    "https://public.example/document",
                    {"topic": "paper"},
                    policy=expected_policy,
                )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "PUBLIC_FIXTURE_CONTENT")
        self.assertEqual(response.url, "https://public.example/document?topic=paper")

    def test_per_request_policy_controls_file_like_request_body_limit(self) -> None:
        session_policy = FetchPolicy(max_request_bytes=4)
        request_policy = FetchPolicy(max_request_bytes=16)
        fetcher = SafeFetcher(session_policy)
        sent_bodies: list[bytes | None] = []

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None, policy=None):
            del address, headers, timeout_seconds, policy
            sent_bodies.append(body)
            return FetchResponse(200, (), b"ok", target.url, (), method)

        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 80))]
        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            fetcher, "_send", side_effect=simulated_send
        ):
            with SafeRequestsSession(fetcher=fetcher) as client:
                response = client.post(
                    "http://public.example/upload",
                    data=BytesIO(b"payload"),
                    policy=request_policy,
                )

        self.assertEqual(response.content, b"ok")
        self.assertEqual(sent_bodies, [b"payload"])

    def test_per_request_policy_requires_a_policy_object(self) -> None:
        with SafeRequestsSession() as client:
            with self.assertRaises(PolicyError):
                client.get("https://public.example/", policy={"allowed_hosts": ["public.example"]})

    def test_per_request_policy_cannot_change_session_redirect_limit(self) -> None:
        with SafeRequestsSession() as client:
            with self.assertRaises(PolicyError):
                client.get("https://public.example/", policy=FetchPolicy(max_redirects=1))

    def test_redirect_limit_cannot_be_raised_after_session_setup(self) -> None:
        with SafeRequestsSession() as client:
            with self.assertRaises(PolicyError):
                client.max_redirects = 100
            self.assertEqual(client.max_redirects, FetchPolicy().max_redirects)

    def test_requests_redirect_loop_stops_at_policy_limit(self) -> None:
        policy = FetchPolicy(max_redirects=1)
        fetcher = SafeFetcher(policy)
        sends: list[str] = []
        public_ip = ipaddress.ip_address("93.184.216.34")
        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (str(public_ip), 80))]

        def simulated_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
            del address, headers, body, timeout_seconds
            sends.append(target.url)
            return FetchResponse(
                302,
                (("Location", "/next"),),
                b"",
                target.url,
                (),
                method,
            )

        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            fetcher, "_send", side_effect=simulated_send
        ):
            with SafeRequestsSession(fetcher=fetcher) as client:
                with self.assertRaises(requests.TooManyRedirects):
                    client.get("http://public.example/start")

        self.assertEqual(sends, ["http://public.example/start", "http://public.example/next"])

    def test_redirect_to_loopback_is_rejected_before_second_send(self) -> None:
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

        records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 80))]
        with patch("safe_egress.client.socket.getaddrinfo", return_value=records), patch.object(
            fetcher, "_send", side_effect=simulated_send
        ):
            with SafeRequestsSession(fetcher=fetcher) as client:
                with self.assertRaises(requests.ConnectionError):
                    client.get("http://public.example/start")

        self.assertEqual(sent, ["http://public.example/start"])

    def test_requests_parser_canonicalization_cannot_hide_loopback(self) -> None:
        fetcher = SafeFetcher()
        suspicious_url = r"http://127.0.0.1\@1.1.1.1"
        prepared_url = requests.Request("GET", suspicious_url).prepare().url
        self.assertEqual(prepared_url, "http://127.0.0.1/%5C@1.1.1.1")

        with patch.object(fetcher, "_send") as send:
            with SafeRequestsSession(fetcher=fetcher) as client:
                with self.assertRaises(requests.ConnectionError):
                    client.get(suspicious_url)

        send.assert_not_called()

    def test_proxy_is_rejected(self) -> None:
        with SafeRequestsSession() as client:
            with self.assertRaises(PolicyError):
                client.get("http://example.com/", proxies={"http": "http://proxy.invalid"})

    def test_custom_mount_cannot_replace_safe_transport(self) -> None:
        with SafeRequestsSession() as client:
            with self.assertRaises(PolicyError):
                client.mount("http://", requests.adapters.HTTPAdapter())
            with self.assertRaises(PolicyError):
                client.mount("http://internal.example/", requests.adapters.HTTPAdapter())

    def test_public_adapter_table_cannot_be_mutated_or_replaced(self) -> None:
        with SafeRequestsSession() as client:
            safe_adapter = client.get_adapter("https://public.example/")
            with self.assertRaises(TypeError):
                client.adapters["https://"] = requests.adapters.HTTPAdapter()
            with self.assertRaises(PolicyError):
                client.adapters = {"https://": requests.adapters.HTTPAdapter()}
            self.assertIs(client.get_adapter("https://public.example/"), safe_adapter)

    def test_cross_origin_redirect_removes_origin_metadata(self) -> None:
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
            with SafeRequestsSession(fetcher=fetcher) as client:
                response = client.get(
                    "https://public.example/start",
                    headers={
                        "Authorization": "Bearer dummy",
                        "Cookie": "session=dummy",
                        "Origin": "https://caller.example",
                    },
                )

        self.assertEqual(response.content, b"PUBLIC_FIXTURE_CONTENT")
        self.assertIn("authorization", sent[0][1])
        self.assertIn("cookie", sent[0][1])
        self.assertIn("origin", sent[0][1])
        self.assertNotIn("authorization", sent[1][1])
        self.assertNotIn("cookie", sent[1][1])
        self.assertNotIn("origin", sent[1][1])

    def test_streaming_response_option_is_rejected(self) -> None:
        with SafeRequestsSession() as client:
            with self.assertRaises(PolicyError):
                client.get("http://example.com/", stream=True)

    def test_raw_requests_sink_reaches_local_canary_but_safe_session_blocks_it(self) -> None:
        """Model raw Requests with a localhost URL and an in-memory canary."""
        accesses: list[str] = []

        class InternalCanaryAdapter(BaseAdapter):
            def send(self, request, **kwargs):
                accesses.append(request.url)
                response = requests.Response()
                response.status_code = 200
                response.url = request.url
                response.request = request
                response._content = b"dummy internal fixture data"
                response._content_consumed = True
                return response

            def close(self):
                return None

        url = "http://127.0.0.1:54321/internal-status"
        # This models the vulnerable raw requests.get sink: application code
        # reaches the local canary without routing through its safe helper.
        with requests.Session() as vulnerable_client:
            vulnerable_client.trust_env = False
            vulnerable_client.mount("http://127.0.0.1", InternalCanaryAdapter())
            vulnerable = vulnerable_client.get(url, timeout=2)
        self.assertEqual(vulnerable.status_code, 200)
        self.assertEqual(vulnerable.content, b"dummy internal fixture data")
        self.assertEqual(accesses, [url])

        # Allow this port so the rejection demonstrates the address policy,
        # not the default port restriction. The safe adapter never calls its
        # transport, so the in-memory canary sees no second request.
        policy = FetchPolicy(allowed_ports=frozenset({54321}), timeout_seconds=2)
        with SafeRequestsSession(policy=policy) as safe_client:
            with self.assertRaises(requests.ConnectionError):
                safe_client.get(url, timeout=2)
        self.assertEqual(accesses, [url])


if __name__ == "__main__":
    unittest.main()
