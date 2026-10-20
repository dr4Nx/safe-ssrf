from __future__ import annotations

import ipaddress
import math
import unittest

from safe_egress import FetchPolicy, PolicyError
from safe_egress.policy import normalize_host


class HostNormalizationTests(unittest.TestCase):
    def test_normalizes_case_idna_and_ip_literals(self) -> None:
        self.assertEqual(normalize_host("ExAmPlE.COM."), "example.com")
        self.assertEqual(normalize_host("bücher.example"), "xn--bcher-kva.example")
        self.assertEqual(normalize_host("2001:0db8::1"), "2001:db8::1")

    def test_rejects_empty_invalid_scoped_and_malformed_hosts(self) -> None:
        for host in ("", ".", "bad host", "a..b", "[::1]", "fe80::1%en0"):
            with self.subTest(host=host), self.assertRaises(PolicyError):
                normalize_host(host)


class FetchPolicyTests(unittest.TestCase):
    def test_host_allowlist_is_exact_and_normalized(self) -> None:
        policy = FetchPolicy(allowed_hosts=frozenset({"Example.COM."}))
        self.assertEqual(policy.check_host("example.com"), "example.com")
        with self.assertRaises(PolicyError):
            policy.check_host("example.com.attacker.test")

    def test_private_exception_is_exact(self) -> None:
        policy = FetchPolicy(allowed_private_hosts=frozenset({"intranet.example"}))
        self.assertTrue(policy.permits_private("INTRANET.EXAMPLE."))
        self.assertFalse(policy.permits_private("intranet.example.attacker.test"))

    def test_rejects_invalid_ports_and_limits(self) -> None:
        for kwargs in (
            {"allowed_ports": frozenset()},
            {"allowed_ports": frozenset({0})},
            {"allowed_ports": frozenset({True})},
            {"allowed_ports": frozenset({443.0})},
            {"max_redirects": -1},
            {"max_redirects": True},
            {"max_redirects": 1.5},
            {"max_response_bytes": 0},
            {"max_response_bytes": True},
            {"max_response_bytes": 1.5},
            {"max_request_bytes": False},
            {"timeout_seconds": 0},
            {"timeout_seconds": True},
            {"timeout_seconds": "5"},
            {"timeout_seconds": math.inf},
            {"timeout_seconds": math.nan},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                FetchPolicy(**kwargs)

    def test_public_classifier_rejects_sensitive_and_transition_ranges(self) -> None:
        denied = (
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "192.0.2.1",
            "::1",
            "::ffff:127.0.0.1",
            "2002:7f00:0001::",
            "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
            "64:ff9b::7f00:1",
        )
        for text in denied:
            address = ipaddress.ip_address(text)
            with self.subTest(address=text):
                self.assertFalse(FetchPolicy.is_public_address(address))

    def test_public_classifier_accepts_public_address(self) -> None:
        self.assertTrue(FetchPolicy.is_public_address(ipaddress.ip_address("93.184.216.34")))


if __name__ == "__main__":
    unittest.main()
