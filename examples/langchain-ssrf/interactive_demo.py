"""Interactively compare vulnerable and Safe Egress LangChain loaders.

Default mode uses in-memory fixtures. Local-service mode starts a loopback
fixture and makes a real vulnerable request to it. Live mode is opt-in.
"""

from __future__ import annotations

import asyncio
import argparse
import ipaddress
import os
import socket
import textwrap
import threading
from typing import Any
from unittest.mock import AsyncMock, patch
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from html.parser import HTMLParser
from urllib.parse import urlsplit

os.environ.setdefault("USER_AGENT", "safe-egress-interactive-demo")
warnings.filterwarnings("ignore", message="For better logging of progress.*")

import aiohttp
from langchain_community.document_loaders.async_html import AsyncHtmlLoader
from langchain_core.documents import Document

from hardened_async_html import SafeAsyncHtmlLoader
from safe_egress import FetchPolicy
from vulnerable_async_html import VulnerableAsyncHtmlLoader


PUBLIC_HTML = "<html><body>PUBLIC FIXTURE CONTENT</body></html>"
INTERNAL_HTML = "<html><body>some vulnerable internal stuff, SIMULATED INTERNAL SERVICE: dummy data</body></html>"
LIVE_BODY_LIMIT = 1_000_000
LIVE_REQUEST_HEADERS = {
    "User-Agent": "safe-egress-langchain-demo/1.0",
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en-US,en;q=0.9",
}


def _to_document(_loader: Any, url: str, text: str) -> Document:
    """Keep the demo focused on fetching rather than HTML parsing."""
    return Document(page_content=text, metadata={"source": url})


class _FakeResponse:
    def __init__(self, body: str) -> None:
        self.body = body

    async def text(self) -> str:
        return self.body


class _FakeRequest:
    def __init__(self, body: str) -> None:
        self.response = _FakeResponse(body)

    async def __aenter__(self) -> _FakeResponse:
        return self.response

    async def __aexit__(self, *args: Any) -> None:
        return None


class _MemoryTransport:
    """Feed one HTTP response to aiohttp without creating a socket."""

    def __init__(self, loop: asyncio.AbstractEventLoop, protocol: Any, response: bytes) -> None:
        self.loop = loop
        self.protocol = protocol
        self.response = response
        self.sent = False
        self.closed = False

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        return default

    def is_closing(self) -> bool:
        return self.closed

    def write(self, data: bytes) -> None:
        if not self.sent:
            self.sent = True
            self.loop.call_soon(self.protocol.data_received, self.response)

    def writelines(self, data: list[bytes]) -> None:
        self.write(b"".join(data))

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self.protocol.connection_lost(None)

    def abort(self) -> None:
        self.close()

    def can_write_eof(self) -> bool:
        return True

    def write_eof(self) -> None:
        self.close()

    def set_write_buffer_limits(self, *args: Any, **kwargs: Any) -> None:
        return None

    def get_write_buffer_size(self) -> int:
        return 0

    def get_write_buffer_limits(self) -> tuple[int, int]:
        return (0, 0)


class _LimitedClientResponse(aiohttp.ClientResponse):
    """Keep the vulnerable live demonstration's response body bounded."""

    async def text(self, encoding: str | None = None, errors: str = "strict") -> str:
        raw = await self.content.read(LIVE_BODY_LIMIT + 1)
        if len(raw) > LIVE_BODY_LIMIT:
            self.close()
            raise ValueError(f"Demo response exceeded {LIVE_BODY_LIMIT} bytes")
        return raw.decode(encoding or self.get_encoding(), errors=errors)


class _VisibleText(HTMLParser):
    _HIDDEN_TAGS = {"script", "style", "noscript", "svg", "template"}
    _BLOCK_TAGS = {
        "address", "article", "blockquote", "br", "dd", "div", "dl", "dt",
        "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2", "h3",
        "h4", "h5", "h6", "header", "hr", "li", "main", "nav", "ol", "p",
        "pre", "section", "table", "td", "th", "tr", "ul",
    }
    _VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden_stack: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        if self.hidden_stack:
            if tag not in self._VOID_TAGS:
                self.hidden_stack.append(tag)
            return
        if tag in self._HIDDEN_TAGS:
            self.hidden_stack.append(tag)
        elif tag in self._BLOCK_TAGS:
            self.parts.append("\n")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in self._VOID_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if self.hidden_stack:
            for index in range(len(self.hidden_stack) - 1, -1, -1):
                if self.hidden_stack[index] == tag:
                    del self.hidden_stack[index:]
                    break
            return
        if tag in self._BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self.hidden_stack:
            return
        value = " ".join(data.split())
        if value:
            self.parts.extend((value, " "))


def _is_internal_host(host: str) -> bool:
    normalized = host.rstrip(".").lower()
    if normalized == "localhost" or normalized.endswith((".internal", ".local")):
        return True
    try:
        return not ipaddress.ip_address(normalized).is_global
    except ValueError:
        return False


def _validate_demo_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter an HTTP(S) URL with a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs with embedded credentials are not accepted")


def _vulnerable_load(url: str, *, simulated_internal: bool = False) -> tuple[str, str]:
    loader = VulnerableAsyncHtmlLoader(url, requests_per_second=1, trust_env=False)
    requested: list[str] = []

    def fake_get(_session: Any, requested_url: str, **kwargs: Any) -> _FakeRequest:
        requested.append(str(requested_url))
        host = urlsplit(str(requested_url)).hostname or ""
        body = INTERNAL_HTML if simulated_internal or _is_internal_host(host) else PUBLIC_HTML
        return _FakeRequest(body)

    try:
        with (
            patch.object(aiohttp.ClientSession, "get", new=fake_get),
            patch.object(AsyncHtmlLoader, "_to_document", new=_to_document),
        ):
            documents = loader.load()
        body = textwrap.shorten(documents[0].page_content, width=52, placeholder="...")
        return f"loaded: {body}", f"aiohttp.get called for {requested[0]} (intercepted)"
    finally:
        loader.session.close()


def _safe_load(
    url: str,
    *,
    dns_records: list[tuple[Any, ...]] | None = None,
    simulated_internal: bool = False,
) -> tuple[str, str]:
    loader = SafeAsyncHtmlLoader(url, requests_per_second=1, ignore_load_errors=False)
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    answer = "10.0.0.8" if simulated_internal or _is_internal_host(host) else "93.184.216.34"
    body = INTERNAL_HTML if simulated_internal or _is_internal_host(host) else PUBLIC_HTML
    response_body = body.encode("utf-8")
    wire_response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: "
        + str(len(response_body)).encode("ascii")
        + b"\r\nConnection: close\r\n\r\n"
        + response_body
    )

    async def fake_getaddrinfo(
        loop: asyncio.AbstractEventLoop,
        requested_host: str,
        port: int,
        *,
        family: int = socket.AF_UNSPEC,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[tuple[Any, ...]]:
        del loop, type, proto, flags
        if dns_records is not None:
            return [record for record in dns_records if family in (socket.AF_UNSPEC, record[0])]
        mapped_ip = "10.0.0.8" if _is_internal_host(requested_host) else "93.184.216.34"
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (mapped_ip, port))]

    async def in_memory_connection(connector: Any, factory: Any, *args: Any, **kwargs: Any):
        del connector, args, kwargs
        loop = asyncio.get_running_loop()
        protocol = factory()
        transport = _MemoryTransport(loop, protocol, wire_response)
        protocol.connection_made(transport)
        return transport, protocol

    try:
        with (
            patch.object(asyncio.BaseEventLoop, "getaddrinfo", new=fake_getaddrinfo),
            patch.object(aiohttp.TCPConnector, "_wrap_create_connection", new=in_memory_connection),
            patch.object(AsyncHtmlLoader, "_to_document", new=_to_document),
        ):
            documents = loader.load()
        body_text = textwrap.shorten(documents[0].page_content, width=52, placeholder="...")
        return f"loaded: {body_text}", f"synthetic DNS -> {answer}; memory response"
    except Exception as exc:
        return f"denied: {type(exc).__name__}: {exc}", "connector not reached"
    finally:
        loader.session.close()


def _live_dns_records(url: str) -> tuple[str, int, list[tuple[Any, ...]], bool]:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme not in {"http", "https"} or not host:
        raise ValueError("Live mode accepts HTTP(S) URLs only")
    default_port = 443 if parsed.scheme == "https" else 80
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, default_port)
    ):
        raise ValueError("Live mode does not accept URL credentials or custom ports")

    port = default_port
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not answers:
        raise OSError(f"{host} resolved to no addresses")
    all_public = all(
        ipaddress.ip_address(answer[4][0]).is_global
        and FetchPolicy().permits_address(ipaddress.ip_address(answer[4][0]))
        for answer in answers
    )
    return host, port, answers, all_public


def _pinned_getaddrinfo(hostname: str, records: list[tuple[Any, ...]]):
    async def getaddrinfo(
        loop: asyncio.AbstractEventLoop,
        requested_host: str,
        port: int,
        *,
        family: int = socket.AF_UNSPEC,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[tuple[Any, ...]]:
        del loop, type, proto, flags
        if requested_host.lower().rstrip(".") != hostname:
            raise OSError("Live demo blocks requests to hosts outside its DNS-pinned URL")
        filtered = [record for record in records if family in (socket.AF_UNSPEC, record[0])]
        if not filtered:
            raise OSError("No pinned address matches the requested address family")
        return filtered

    return getaddrinfo


def _run_live_loader(
    loader_type: Any, url: str, hostname: str, records: list[tuple[Any, ...]]
) -> tuple[str, str, str]:
    loader = loader_type(
        url,
        header_template=dict(LIVE_REQUEST_HEADERS),
        requests_per_second=1,
        trust_env=False,
        requests_kwargs={
            "timeout": aiohttp.ClientTimeout(total=8),
            "allow_redirects": False,
        },
    )
    original_session = aiohttp.ClientSession

    def bounded_session(*args: Any, **kwargs: Any):
        kwargs.setdefault("response_class", _LimitedClientResponse)
        return original_session(*args, **kwargs)

    try:
        with (
            patch.object(aiohttp, "ClientSession", new=bounded_session),
            patch.object(
                asyncio.BaseEventLoop,
                "getaddrinfo",
                new=_pinned_getaddrinfo(hostname, records),
            ),
            patch.object(AsyncHtmlLoader, "_to_document", new=_to_document),
        ):
            documents = loader.load()
        return "loaded", f"real request to pinned public IP; {hostname}", documents[0].page_content
    except Exception as exc:
        return f"request failed: {type(exc).__name__}: {exc}", "real request attempted", ""
    finally:
        loader.session.close()


def _print_live_result(label: str, url: str, result: tuple[str, str, str]) -> None:
    outcome, transport, html = result
    parser = _VisibleText()
    parser.feed(html)
    visible_text = "".join(parser.parts)
    lines = [
        line
        for paragraph in visible_text.splitlines()
        for line in textwrap.wrap(paragraph.strip(), width=76)
    ][:10]
    print(f"\n{label}")
    print(f"  URL: {url}")
    print(f"  Result: {outcome}")
    print(f"  Transport: {transport}")
    print(f"  Response body: {len(html.encode('utf-8'))} bytes")
    print("  Page text preview (up to 10 lines):")
    if lines:
        for line in lines:
            print(f"    {line}")
    else:
        print("    (no readable text in the response)")


def _print_live_comparison(
    url: str,
    vulnerable: tuple[str, str, str],
    safe: tuple[str, str, str],
) -> None:
    print("\nLoader comparison")
    _print_live_result("VULNERABLE LOADER", url, vulnerable)
    _print_live_result("SAFE EGRESS LOADER", url, safe)


def _run_local_service_demo() -> None:
    requests_seen: list[str] = []
    response_body = INTERNAL_HTML.encode("utf-8")

    class InternalServiceHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests_seen.append(f"GET {self.path}")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(response_body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(response_body)

        def log_message(self, format: str, *args: Any) -> None:
            del format, args

    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), InternalServiceHandler)
    except OSError as exc:
        raise RuntimeError(f"Could not bind the local demo service: {exc}") from exc
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    fixture_url = f"http://127.0.0.1:{server.server_port}/internal-status"
    print(f"Dummy internal service listening at {fixture_url}")
    print("The vulnerable loader will request it; Safe Egress should reject it.\n")
    try:
        entered_url = input(f"URL [{fixture_url}]: ").strip()
        url = entered_url or fixture_url
        _validate_demo_url(url)
        parsed = urlsplit(url)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.port != server.server_port
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("Use the displayed URL so the demo only targets its own local service")

        vulnerable_loader = VulnerableAsyncHtmlLoader(
            url,
            requests_per_second=1,
            trust_env=False,
            requests_kwargs={"timeout": aiohttp.ClientTimeout(total=3)},
        )
        try:
            with patch.object(AsyncHtmlLoader, "_to_document", new=_to_document):
                vulnerable_documents = vulnerable_loader.load()
            vulnerable_result = "loaded"
            vulnerable_html = vulnerable_documents[0].page_content
        except Exception as exc:
            vulnerable_result = f"request failed: {type(exc).__name__}: {exc}"
            vulnerable_html = ""
        finally:
            vulnerable_loader.session.close()
        vulnerable_count = len(requests_seen)

        safe_loader = SafeAsyncHtmlLoader(
            url,
            requests_per_second=1,
            ignore_load_errors=False,
            trust_env=False,
            requests_kwargs={"timeout": aiohttp.ClientTimeout(total=3)},
        )
        safe_loader.safe_policy = FetchPolicy(
            allowed_ports=frozenset({80, 443, server.server_port})
        )
        connector_attempt = AsyncMock()
        try:
            with (
                patch.object(AsyncHtmlLoader, "_to_document", new=_to_document),
                patch.object(aiohttp.TCPConnector, "_create_connection", new=connector_attempt),
            ):
                safe_loader.load()
            safe_result = "unexpectedly loaded the internal response"
        except Exception as exc:
            safe_result = f"denied: {type(exc).__name__}: {exc}"
        finally:
            safe_loader.session.close()
        safe_count = len(requests_seen) - vulnerable_count

        _print_live_comparison(
            url,
            (
                vulnerable_result,
                "real HTTP request to the local dummy service",
                vulnerable_html,
            ),
            (
                safe_result,
                "connector not reached",
                "",
            ),
        )
        print("\nDummy service diagnostics")
        print(f"  Requests reaching service: vulnerable={vulnerable_count}, safe={safe_count}")
        print(f"  Safe connector opened: {connector_attempt.await_count > 0}")
        print("\nDummy service request log:")
        for item in requests_seen:
            print(f"  {item}")
        if not requests_seen:
            print("  (no requests)")
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live",
        action="store_true",
        help="make real requests to public HTTP(S) URLs",
    )
    parser.add_argument(
        "--local-service",
        action="store_true",
        help="start a dummy loopback HTTP service for a real vulnerable fetch",
    )
    args = parser.parse_args()
    if args.live and args.local_service:
        parser.error("choose either --live or --local-service")
    if args.local_service:
        try:
            _run_local_service_demo()
        except (OSError, RuntimeError, ValueError) as exc:
            parser.exit(2, f"Demo could not run: {exc}\n")
        return
    if args.live:
        try:
            _run_local_service_demo()
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"Local-service comparison unavailable: {exc}\n")
        print("Live mode: enter an HTTP(S) URL on port 80 or 443; redirects are disabled.")
        print("Public DNS answers are checked and pinned. No URL credentials are accepted.")
        print("Private or mixed DNS answers use the internal fixture, never a real request.")
        print("Each loader makes a separate request; page content may vary between responses.")
        print("The text preview omits scripts, styles, SVG, and template contents.")
        print(f"Live response bodies are capped at {LIVE_BODY_LIMIT} bytes. Type q to quit.\n")
    else:
        print("Type an HTTP(S) URL. Try http://127.0.0.1/internal-status or http://public.example/page.")
        print("All requests and DNS answers are simulated; no URL is contacted. Type q to quit.\n")
    while True:
        url = input("URL> ").strip()
        if url.lower() in {"q", "quit", "exit"}:
            break
        try:
            _validate_demo_url(url)
            if args.live:
                host, _, records, public = _live_dns_records(url)
                if public:
                    vulnerable_result = _run_live_loader(
                        VulnerableAsyncHtmlLoader, url, host, records
                    )
                    safe_result = _run_live_loader(SafeAsyncHtmlLoader, url, host, records)
                    _print_live_comparison(url, vulnerable_result, safe_result)
                    print()
                    continue
                else:
                    # Show the vulnerable handoff without connecting to a private service.
                    vulnerable_result, vulnerable_path = _vulnerable_load(
                        url, simulated_internal=True
                    )
                    safe_result, safe_path = _safe_load(
                        url, dns_records=records, simulated_internal=True
                    )
            else:
                vulnerable_result, vulnerable_path = _vulnerable_load(url)
                safe_result, safe_path = _safe_load(url)
        except Exception as exc:
            print(f"Input error: {exc}\n")
            continue

        print(f"{'VULNERABLE LOADER':52} | {'SAFE EGRESS LOADER':52}")
        print("-" * 107)
        print(f"{vulnerable_result:52} | {safe_result:52}")
        print(f"{vulnerable_path:52} | {safe_path:52}\n")


if __name__ == "__main__":
    main()
