#!/usr/bin/env python3
"""Run a fixture-only PyJWT SSRF reproduction for one source checkout.

Only the HTTP transport is synthetic. PyJWT's actual PyJWKClient source and
urllib's actual redirect/error handlers run. No socket is opened.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import io
import ipaddress
import json
import socket
import sys
import tempfile
import urllib.request
from email.message import Message
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import patch
from urllib.response import addinfourl


PUBLIC_URL = "http://public-fixture.test/jwks"
INTERNAL_URL = "http://127.0.0.1/internal-status"
PUBLIC_BODY = b'{"keys":[],"fixture":"public JWKS fixture"}'
INTERNAL_BODY = b'{"keys":[],"fixture":"SIMULATED INTERNAL SERVICE"}'
EXPECTED_VERSIONS = {
    "vulnerable": "2.13.0",
    "fixed": "2.14.0",
    "hardened": "2.13.0",
    "vulnerable-scheme": "2.12.1",
    "fixed-scheme": "2.13.0",
    "hardened-scheme": "2.12.1",
    # These modes deliberately skip a version pin while asserting behavior for
    # a separately identified checkout; use them for current upstream source.
    "fixed-current": None,
    "fixed-current-scheme": None,
}


class _FixtureHTTPHandler(urllib.request.BaseHandler):
    handler_order = 100

    def __init__(self, *, redirect: bool) -> None:
        self.redirect = redirect
        self.requests: list[dict[str, Any]] = []

    def http_open(self, request: urllib.request.Request):
        self.requests.append(
            {
                "url": request.full_url,
                "headers": {name.lower(): value for name, value in request.header_items()},
            }
        )
        headers = Message()
        if self.redirect and request.full_url == PUBLIC_URL:
            headers["Location"] = INTERNAL_URL
            body, status = b"", 302
        else:
            body = INTERNAL_BODY if request.full_url == INTERNAL_URL else PUBLIC_BODY
            headers["Content-Type"] = "application/json"
            status = 200
        response = addinfourl(io.BytesIO(body), headers, request.full_url, code=status)
        response.msg = "Synthetic fixture response"
        return response


def _fixture_opener(*, redirect: bool, handlers: tuple[Any, ...] = ()):
    opener = urllib.request.OpenerDirector()
    builtin_handlers: tuple[Any, ...] = (
        _FixtureHTTPHandler(redirect=redirect),
        urllib.request.FileHandler(),
        urllib.request.HTTPDefaultErrorHandler(),
        *handlers,
        urllib.request.HTTPErrorProcessor(),
    )
    for handler in builtin_handlers:
        opener.add_handler(handler)
    fixture_handler = builtin_handlers[0]
    return opener, fixture_handler


@contextmanager
def _patched_default_opener(*, redirect: bool) -> Iterator[_FixtureHTTPHandler]:
    opener, fixture = _fixture_opener(
        redirect=redirect,
        handlers=(urllib.request.HTTPRedirectHandler(),),
    )
    with patch.object(urllib.request, "_opener", opener):
        yield fixture


@contextmanager
def _patched_build_opener(*, redirect: bool) -> Iterator[_FixtureHTTPHandler]:
    captured: list[_FixtureHTTPHandler] = []

    def build_opener(*handlers: Any):
        opener, fixture = _fixture_opener(redirect=redirect, handlers=handlers)
        captured.append(fixture)
        return opener

    with patch.object(urllib.request, "build_opener", side_effect=build_opener):
        yield captured


def _load_pyjwt(repo: Path, mode: str):
    if not (repo / "jwt" / "jwks_client.py").is_file():
        raise SystemExit(f"{repo} does not contain jwt/jwks_client.py")
    sys.path.insert(0, str(repo.resolve()))
    import jwt
    from jwt import PyJWKClient
    from jwt.exceptions import PyJWKClientConnectionError

    expected = EXPECTED_VERSIONS[mode]
    if expected is not None and jwt.__version__ != expected:
        raise SystemExit(f"Expected PyJWT {expected}, found {jwt.__version__} at {jwt.__file__}")
    return jwt, PyJWKClient, PyJWKClientConnectionError


def _run_source_mode(repo: Path, mode: str) -> dict[str, Any]:
    _, PyJWKClient, PyJWKClientConnectionError = _load_pyjwt(repo, mode)
    if mode.endswith("-scheme"):
        return _run_scheme_mode(repo, mode, PyJWKClient, PyJWKClientConnectionError)

    headers = {"Authorization": "Bearer dummy-evaluation-token"}
    output: dict[str, Any] = {"repository": str(repo.resolve()), "mode": mode}

    if mode == "vulnerable":
        client = PyJWKClient(PUBLIC_URL, headers=headers, timeout=1, cache_jwk_set=False)
        with _patched_default_opener(redirect=True) as fixture:
            result = client.fetch_data()
        output["requests"] = fixture.requests
        output["returned_fixture"] = result.get("fixture")
        output["internal_service_reached"] = any(item["url"] == INTERNAL_URL for item in fixture.requests)
        output["dummy_authorization_seen_at_internal"] = any(
            item["url"] == INTERNAL_URL
            and item["headers"].get("authorization") == "Bearer dummy-evaluation-token"
            for item in fixture.requests
        )
        if not output["internal_service_reached"] or result.get("fixture") != "SIMULATED INTERNAL SERVICE":
            raise AssertionError("The vulnerable PyJWT control did not follow the synthetic redirect")
        return output

    if mode in {"fixed", "fixed-current"}:
        client = PyJWKClient(PUBLIC_URL, headers=headers, timeout=1, cache_jwk_set=False)
        with _patched_build_opener(redirect=True) as fixture_handlers:
            try:
                client.fetch_data()
            except PyJWKClientConnectionError:
                pass
            else:
                raise AssertionError("The fixed PyJWT source should reject an HTTP redirect")
        redirect_fixture = fixture_handlers[0]
        if any(item["url"] == INTERNAL_URL for item in redirect_fixture.requests):
            raise AssertionError("The fixed PyJWT source contacted the simulated internal service")

        public_client = PyJWKClient(PUBLIC_URL, timeout=1, cache_jwk_set=False)
        with _patched_build_opener(redirect=False) as fixture_handlers:
            public_result = public_client.fetch_data()
        public_fixture = fixture_handlers[0]
        if public_result.get("fixture") != "public JWKS fixture":
            raise AssertionError("The fixed PyJWT source failed its public JWKS utility case")
        output.update(
            {
                "redirect_requests": redirect_fixture.requests,
                "loopback_blocked": not any(item["url"] == INTERNAL_URL for item in redirect_fixture.requests),
                "public_requests": public_fixture.requests,
                "public_fixture_returned": public_result.get("fixture"),
            }
        )
        return output

    if mode == "hardened":
        from safe_egress import FetchPolicy, FetchResponse
        sys.path.insert(0, str(Path(__file__).parent.resolve()))
        from safe_client import SafePyJWKClient

        policy = FetchPolicy(max_redirects=2)
        client = SafePyJWKClient(PUBLIC_URL, policy=policy, headers=headers, timeout=1, cache_jwk_set=False)
        checked: list[str] = []
        public_ip = ipaddress.ip_address("93.184.216.34")
        dns_records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (str(public_ip), 80))]

        def simulated_send(target, address, request_headers, *, method="GET", body=None, timeout_seconds=None):
            checked.append(target.url)
            if address != public_ip:
                raise AssertionError("Fixture sent to an unexpected address")
            return FetchResponse(
                302,
                (("Location", INTERNAL_URL),),
                b"",
                target.url,
                (),
                method,
            )

        with patch("safe_egress.client.socket.getaddrinfo", return_value=dns_records), patch.object(
            client._safe_opener.fetcher, "_send", side_effect=simulated_send
        ):
            try:
                client.fetch_data()
            except PyJWKClientConnectionError:
                pass
            else:
                raise AssertionError("The hardened PyJWT client should reject the loopback redirect")

        utility_client = SafePyJWKClient(PUBLIC_URL, policy=policy, timeout=1, cache_jwk_set=False)

        def public_send(target, address, request_headers, *, method="GET", body=None, timeout_seconds=None):
            checked.append(target.url)
            return FetchResponse(
                200,
                (("Content-Type", "application/json"),),
                PUBLIC_BODY,
                target.url,
                (),
                method,
            )

        with patch("safe_egress.client.socket.getaddrinfo", return_value=dns_records), patch.object(
            utility_client._safe_opener.fetcher, "_send", side_effect=public_send
        ):
            public_result = utility_client.fetch_data()
        if public_result.get("fixture") != "public JWKS fixture":
            raise AssertionError("The hardened PyJWT client failed its public JWKS utility case")
        loopback_sent = any(url == INTERNAL_URL for url in checked)
        if loopback_sent:
            raise AssertionError("Safe Egress sent a request to the synthetic internal service")
        output.update(
            {
                "safe_egress_checked_urls": checked,
                "loopback_blocked": not loopback_sent,
                "public_fixture_returned": public_result.get("fixture"),
                "network": "in-memory transport and synthetic DNS only; no sockets opened",
            }
        )
        return output

    raise AssertionError(f"Unhandled mode {mode}")


def _run_scheme_mode(repo: Path, mode: str, PyJWKClient: Any, PyJWKClientConnectionError: Any):
    from safe_egress import FetchPolicy, FetchResponse

    output: dict[str, Any] = {"repository": str(repo.resolve()), "mode": mode}
    with tempfile.TemporaryDirectory(prefix="safe-egress-pyjwt-") as directory:
        dummy_jwks = Path(directory, "dummy-jwks.json")
        dummy_jwks.write_bytes(b'{"keys":[],"fixture":"SIMULATED LOCAL FILE"}')
        file_uri = dummy_jwks.as_uri()

        if mode == "vulnerable-scheme":
            client = PyJWKClient(file_uri, cache_jwk_set=False)
            with _patched_default_opener(redirect=False):
                result = client.fetch_data()
            if result.get("fixture") != "SIMULATED LOCAL FILE":
                raise AssertionError("The vulnerable PyJWT source did not read the dummy file fixture")
            output.update(
                {
                    "file_scheme_accepted": True,
                    "returned_fixture": result.get("fixture"),
                    "target": "temporary test-owned dummy file only",
                }
            )
            return output

        if mode in {"fixed-scheme", "fixed-current-scheme"}:
            from jwt.exceptions import PyJWKClientError

            try:
                PyJWKClient(file_uri, cache_jwk_set=False)
            except PyJWKClientError:
                pass
            else:
                raise AssertionError("The fixed PyJWT source should reject non-HTTP(S) JWKS URIs")
            public_client = PyJWKClient(PUBLIC_URL, timeout=1, cache_jwk_set=False)
            with _patched_build_opener(redirect=False) as fixture_handlers:
                public_result = public_client.fetch_data()
            if public_result.get("fixture") != "public JWKS fixture":
                raise AssertionError("The fixed PyJWT source failed its public JWKS utility case")
            output.update(
                {
                    "file_scheme_rejected_at_construction": True,
                    "public_fixture_returned": public_result.get("fixture"),
                    "public_requests": fixture_handlers[0].requests,
                }
            )
            return output

        if mode == "hardened-scheme":
            sys.path.insert(0, str(Path(__file__).parent.resolve()))
            from safe_client import SafePyJWKClient

            client = SafePyJWKClient(file_uri, policy=FetchPolicy(), cache_jwk_set=False)
            try:
                client.fetch_data()
            except PyJWKClientConnectionError:
                pass
            else:
                raise AssertionError("SafeUrllibOpener should reject the file URI")

            utility_client = SafePyJWKClient(PUBLIC_URL, policy=FetchPolicy(), cache_jwk_set=False)
            public_ip = ipaddress.ip_address("93.184.216.34")
            dns_records = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (str(public_ip), 80))]
            requests: list[str] = []

            def public_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
                requests.append(target.url)
                return FetchResponse(
                    200,
                    (("Content-Type", "application/json"),),
                    PUBLIC_BODY,
                    target.url,
                    (),
                    method,
                )

            with patch("safe_egress.client.socket.getaddrinfo", return_value=dns_records), patch.object(
                utility_client._safe_opener.fetcher, "_send", side_effect=public_send
            ):
                public_result = utility_client.fetch_data()
            if public_result.get("fixture") != "public JWKS fixture":
                raise AssertionError("The hardened PyJWT source failed its public JWKS utility case")
            output.update(
                {
                    "file_scheme_rejected": True,
                    "public_fixture_returned": public_result.get("fixture"),
                    "public_requests": requests,
                    "network": "temporary dummy file, synthetic DNS, and in-memory HTTP only",
                }
            )
            return output

    raise AssertionError(f"Unhandled mode {mode}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, type=Path, help="PyJWT source checkout for the selected revision")
    parser.add_argument("--mode", choices=tuple(EXPECTED_VERSIONS), required=True)
    args = parser.parse_args()
    result = _run_source_mode(args.repo, args.mode)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
