from __future__ import annotations

import ast
from dataclasses import dataclass, field
from html.parser import HTMLParser
import importlib.util
import ipaddress
import os
import socket
import sys
import types
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import requests
from requests.adapters import BaseAdapter

from safe_egress import FetchPolicy
from safe_egress.client import FetchResponse, SafeFetcher


ROOT = Path(__file__).resolve().parents[2]
VULNERABLE_REPO = Path(
    os.environ.get("LANGCHAIN_SPLITTERS_VULNERABLE", ROOT.parent / "langchain-text-splitters-vuln")
).resolve()
FIXED_REPO = Path(
    os.environ.get("LANGCHAIN_SPLITTERS_FIXED", ROOT.parent / "langchain-text-splitters-fixed-1.1.2")
).resolve()
PUBLIC_URL = "http://public.example/page"
INTERNAL_URL = "http://127.0.0.1/internal"
PUBLIC_HTML = b"<html><h1>Public title</h1><p>Public report body</p></html>"
INTERNAL_HTML = b"<html><h1>SIMULATED INTERNAL SERVICE</h1></html>"

_INTEGRATION_SPEC = importlib.util.spec_from_file_location(
    "_safe_egress_text_splitters_integration",
    Path(__file__).with_name("integration.py"),
)
if _INTEGRATION_SPEC is None or _INTEGRATION_SPEC.loader is None:
    raise ImportError("Could not load the Safe Egress integration factory")
_INTEGRATION_MODULE = importlib.util.module_from_spec(_INTEGRATION_SPEC)
_INTEGRATION_SPEC.loader.exec_module(_INTEGRATION_MODULE)
safe_egress_client_factory = _INTEGRATION_MODULE.ssrf_safe_client


@dataclass(frozen=True)
class Document:
    page_content: str
    metadata: dict[str, Any] = field(default_factory=dict)


class _TextCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        cleaned = data.strip()
        if cleaned:
            self.parts.append(cleaned)


class _SplitterInstance:
    """Small parser stand-in; the production URL-fetch method is loaded verbatim."""

    def split_text(self, html: str) -> list[Document]:
        parser = _TextCollector()
        parser.feed(html)
        content = " ".join(parser.parts)
        return [Document(page_content=content)] if content else []


def _load_fetch_method(repository: Path):
    source = repository / "libs/text-splitters/langchain_text_splitters/html.py"
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    splitter = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "HTMLHeaderTextSplitter"
    )
    method = next(
        node for node in splitter.body
        if isinstance(node, ast.FunctionDef) and node.name == "split_text_from_url"
    )

    def deprecated(**_kwargs: Any):
        return lambda function: function

    namespace: dict[str, Any] = {
        "Any": Any,
        "Document": Document,
        "deprecated": deprecated,
        "requests": requests,
    }
    module = ast.Module(body=[method], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(source), "exec"), namespace)
    return namespace["split_text_from_url"]


def _core_package_modules(core_root: Path) -> dict[str, types.ModuleType]:
    package = types.ModuleType("langchain_core")
    package.__path__ = [str(core_root / "langchain_core")]
    security = types.ModuleType("langchain_core._security")
    security.__path__ = [str(core_root / "langchain_core" / "_security")]
    return {
        "langchain_core": package,
        "langchain_core._security": security,
    }


def _load_actual_fixed_splitter(repository: Path, modules: dict[str, types.ModuleType]):
    """Import the real splitter implementation with lightweight core type stubs."""
    from importlib.util import find_spec

    if find_spec("bs4") is None:
        raise unittest.SkipTest("install BeautifulSoup to exercise the production HTML parser")

    api = types.ModuleType("langchain_core._api")

    def identity_decorator(*args: Any, **kwargs: Any):
        del kwargs
        if len(args) == 1 and callable(args[0]):
            return args[0]
        return lambda function: function

    api.beta = identity_decorator  # type: ignore[attr-defined]
    api.deprecated = identity_decorator  # type: ignore[attr-defined]
    documents = types.ModuleType("langchain_core.documents")

    class _BaseDocumentTransformer:
        pass

    documents.BaseDocumentTransformer = _BaseDocumentTransformer  # type: ignore[attr-defined]
    documents.Document = Document  # type: ignore[attr-defined]
    package = types.ModuleType("langchain_text_splitters")
    package.__path__ = []
    character = types.ModuleType("langchain_text_splitters.character")

    class _RecursiveCharacterTextSplitter:
        pass

    character.RecursiveCharacterTextSplitter = _RecursiveCharacterTextSplitter  # type: ignore[attr-defined]
    modules.update(
        {
            "langchain_core._api": api,
            "langchain_core.documents": documents,
            "langchain_text_splitters": package,
            "langchain_text_splitters.character": character,
        }
    )
    for name, module in modules.items():
        sys.modules[name] = module

    source = repository / "libs/text-splitters/langchain_text_splitters/html.py"
    name = "langchain_text_splitters.html"
    spec = importlib.util.spec_from_file_location(name, source)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load {source}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module.HTMLHeaderTextSplitter(headers_to_split_on=[("h1", "title")])


def _load_core_module(name: str, path: Path) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class _RequestsFixtureAdapter(BaseAdapter):
    def __init__(self, *, redirect: bool) -> None:
        self.redirect = redirect
        self.requested_urls: list[str] = []
        self.internal_accessed = False

    def send(self, request, **kwargs):  # type: ignore[no-untyped-def]
        del kwargs
        self.requested_urls.append(request.url)
        response = requests.Response()
        response.request = request
        response.url = request.url
        if request.url == PUBLIC_URL and self.redirect:
            response.status_code = 302
            response.headers["Location"] = INTERNAL_URL
            body = b""
        elif request.url == INTERNAL_URL:
            self.internal_accessed = True
            response.status_code = 200
            body = INTERNAL_HTML
        else:
            response.status_code = 200
            body = PUBLIC_HTML
        response._content = body
        response._content_consumed = True
        return response

    def close(self) -> None:
        return None


def _requests_get_with_fixture(adapter: _RequestsFixtureAdapter):
    def get(url: str, **kwargs: Any):
        with requests.Session() as session:
            session.mount("http://", adapter)
            return session.get(url, **kwargs)

    return get


class LangChainTextSplittersSSRFFixtureTests(unittest.TestCase):
    def _public_dns(self, _host: str, _port: int, *args: Any, **kwargs: Any):
        del args, kwargs
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", 80),
            )
        ]

    def test_vulnerable_requests_redirect_reaches_simulated_internal_service(self) -> None:
        adapter = _RequestsFixtureAdapter(redirect=True)
        fetch_method = _load_fetch_method(VULNERABLE_REPO)
        core_root = VULNERABLE_REPO / "libs/core"
        modules = _core_package_modules(core_root)
        with patch.dict(sys.modules, modules):
            _load_core_module(
                "langchain_core._security._ssrf_protection",
                core_root / "langchain_core/_security/_ssrf_protection.py",
            )
            with patch.object(socket, "getaddrinfo", side_effect=self._public_dns), patch.object(
                requests, "get", new=_requests_get_with_fixture(adapter)
            ):
                documents = fetch_method(_SplitterInstance(), PUBLIC_URL)

        self.assertTrue(adapter.internal_accessed)
        self.assertEqual(adapter.requested_urls, [PUBLIC_URL, INTERNAL_URL])
        self.assertIn("SIMULATED INTERNAL SERVICE", documents[0].page_content)

    def test_maintainer_fixed_source_blocks_redirect_to_loopback(self) -> None:
        from httpx import HTTPTransport

        adapter = _HttpxFixtureTransport(redirect=True)
        fetch_method = _load_fetch_method(FIXED_REPO)
        core_root = FIXED_REPO / "libs/core"
        modules = _core_package_modules(core_root)
        with patch.dict(sys.modules, modules):
            _load_core_module(
                "langchain_core._security._transport",
                core_root / "langchain_core/_security/_transport.py",
            )
            blocked_error = sys.modules[
                "langchain_core._security._exceptions"
            ].SSRFBlockedError
            with patch.object(socket, "getaddrinfo", side_effect=self._public_dns), patch.object(
                HTTPTransport, "handle_request", new=adapter.handle_request
            ):
                with self.assertRaises(blocked_error):
                    fetch_method(_SplitterInstance(), PUBLIC_URL)

        self.assertFalse(adapter.internal_accessed)
        self.assertEqual(adapter.public_requests, 1)

        adapter = _HttpxFixtureTransport(redirect=False)
        with patch.dict(sys.modules, modules):
            _load_core_module(
                "langchain_core._security._transport",
                core_root / "langchain_core/_security/_transport.py",
            )
            with patch.object(socket, "getaddrinfo", side_effect=self._public_dns), patch.object(
                HTTPTransport, "handle_request", new=adapter.handle_request
            ):
                documents = fetch_method(_SplitterInstance(), PUBLIC_URL)

        self.assertEqual(adapter.public_requests, 1)
        self.assertEqual(documents[0].page_content, "Public title Public report body")

    def test_safe_egress_factory_blocks_redirect_and_preserves_public_fetch(self) -> None:
        adapter = _SafeFetcherFixture(redirect=True)
        fetch_method = _load_fetch_method(FIXED_REPO)
        core_root = FIXED_REPO / "libs/core"
        modules = _core_package_modules(core_root)
        transport_module = types.ModuleType("langchain_core._security._transport")

        transport_module.ssrf_safe_client = safe_egress_client_factory  # type: ignore[attr-defined]
        modules["langchain_core._security._transport"] = transport_module

        with patch.dict(sys.modules, modules), patch.object(
            socket, "getaddrinfo", side_effect=self._public_dns
        ), patch.object(SafeFetcher, "_send", new=adapter.send):
            with self.assertRaises(httpx.RequestError):
                fetch_method(_SplitterInstance(), PUBLIC_URL)

        self.assertEqual(adapter.requested_urls, [PUBLIC_URL])
        self.assertFalse(adapter.internal_accessed)

        adapter = _SafeFetcherFixture(redirect=False)
        with patch.dict(sys.modules, modules), patch.object(
            socket, "getaddrinfo", side_effect=self._public_dns
        ), patch.object(SafeFetcher, "_send", new=adapter.send):
            documents = fetch_method(_SplitterInstance(), PUBLIC_URL)

        self.assertEqual(adapter.requested_urls, [PUBLIC_URL])
        self.assertEqual(documents[0].page_content, "Public title Public report body")

    def test_production_html_parser_keeps_public_fetch_functional(self) -> None:
        adapter = _SafeFetcherFixture(redirect=False)
        core_root = FIXED_REPO / "libs/core"
        modules = _core_package_modules(core_root)
        transport_module = types.ModuleType("langchain_core._security._transport")
        transport_module.ssrf_safe_client = safe_egress_client_factory  # type: ignore[attr-defined]
        modules["langchain_core._security._transport"] = transport_module

        with patch.dict(sys.modules, modules):
            splitter = _load_actual_fixed_splitter(FIXED_REPO, modules)
            with patch.object(socket, "getaddrinfo", side_effect=self._public_dns), patch.object(
                SafeFetcher, "_send", new=adapter.send
            ):
                documents = splitter.split_text_from_url(PUBLIC_URL)

        self.assertEqual(adapter.requested_urls, [PUBLIC_URL])
        self.assertEqual(
            [(document.page_content, document.metadata) for document in documents],
            [
                ("Public title", {"title": "Public title"}),
                ("Public report body", {"title": "Public title"}),
            ],
        )


class _HttpxFixtureTransport:
    def __init__(self, *, redirect: bool) -> None:
        self.redirect = redirect
        self.public_requests = 0
        self.internal_accessed = False

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        host = request.headers.get("host", "")
        if host.lower().startswith("127.0.0.1") or request.url.host == "127.0.0.1":
            self.internal_accessed = True
            body = INTERNAL_HTML
            status = 200
            headers: dict[str, str] = {}
        else:
            self.public_requests += 1
            if self.redirect:
                body = b""
                status = 302
                headers = {"Location": INTERNAL_URL}
            else:
                body = PUBLIC_HTML
                status = 200
                headers = {}
        return httpx.Response(status, headers=headers, content=body, request=request)


class _SafeFetcherFixture:
    def __init__(self, *, redirect: bool) -> None:
        self.redirect = redirect
        self.requested_urls: list[str] = []
        self.internal_accessed = False

    def send(
        self,
        target,
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
        headers,
        *,
        method: str = "GET",
        body: bytes | None = None,
        timeout_seconds: float | None = None,
        connect_timeout_seconds: float | None = None,
        policy: FetchPolicy | None = None,
    ) -> FetchResponse:
        del address, headers, body, timeout_seconds, connect_timeout_seconds, policy
        self.requested_urls.append(target.url)
        if target.url == PUBLIC_URL and self.redirect:
            return FetchResponse(
                status_code=302,
                headers=(("Location", INTERNAL_URL),),
                content=b"",
                url=target.url,
                history=(),
                method=method,
            )
        if target.url == INTERNAL_URL:
            self.internal_accessed = True
            content = INTERNAL_HTML
        else:
            content = PUBLIC_HTML
        return FetchResponse(
            status_code=200,
            headers=(("Content-Type", "text/html; charset=utf-8"),),
            content=content,
            url=target.url,
            history=(),
            method=method,
            peer_ip="93.184.216.34",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
