"""Integration experiment against the vulnerable LangChain benchmark checkout.

Run this using the Poetry environment described in examples/langchain-ssrf/README.md.
All network calls are replaced with an in-memory controlled response.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any
from unittest.mock import patch

import aiohttp
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
import pytest

from safe_egress import FetchPolicy, FetchResponse, SafeFetcher
from langchain_community.retrievers.web_research import WebResearchRetriever

from hardened_async_html import SafeWebResearchAsyncHtmlLoader


INTERNAL_URL = "http://127.0.0.1:8080/internal-status"
PUBLIC_URL = "https://example.com/research-page"


class _Search:
    """Stand-in search provider that returns one controlled URL."""

    def __init__(self, url: str) -> None:
        self.url = url

    def results(self, query: str, count: int) -> list[dict[str, str]]:
        return [{"link": self.url}]


class _QuestionChain:
    def __call__(self, inputs: dict[str, str]) -> dict[str, list[str]]:
        return {"text": ["1. harmless test query"]}


class _VectorStore:
    """In-memory vector-store stand-in so no database service is needed."""

    def __init__(self) -> None:
        self.documents: list[Document] = []

    def add_documents(self, documents: list[Document]) -> None:
        self.documents.extend(documents)

    def similarity_search(self, query: str) -> list[Document]:
        return list(self.documents)


class _IdentityHtmlTransformer:
    def transform_documents(self, documents: list[Document]) -> list[Document]:
        return documents


def _retriever(url: str, store: _VectorStore | None = None) -> WebResearchRetriever:
    # Build the real LangChain retriever, but inject local search, chain, and
    # vector-store stand-ins so the test needs no API keys or external services.
    return WebResearchRetriever.construct(
        vectorstore=store or _VectorStore(),
        llm_chain=_QuestionChain(),
        search=_Search(url),
        num_search_results=1,
        text_splitter=RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=0),
        url_database=[],
        trust_env=False,
    )


class _FakeAiohttpResponse:
    """Minimal async response used to exercise the vulnerable loader safely."""

    status = 200

    async def text(self) -> str:
        return "<html><body>SIMULATED INTERNAL SERVICE: dummy data</body></html>"


class _FakeRequestContext:
    async def __aenter__(self) -> _FakeAiohttpResponse:
        return _FakeAiohttpResponse()

    async def __aexit__(self, *args: Any) -> None:
        return None


class _MemoryTransport:
    """A minimal asyncio transport that feeds one HTTP response to aiohttp."""

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


def test_vulnerable_langchain_loader_sends_search_url_to_aiohttp() -> None:
    """The unguarded benchmark path forwards a search URL to aiohttp.

    The patched ``get`` records the destination instead of opening a socket.
    The assertion therefore proves the URL reaches the network boundary, not
    that this test contacts the loopback service.
    """
    sent_urls: list[str] = []

    def fake_get(_session: Any, url: str, **kwargs: Any) -> _FakeRequestContext:
        sent_urls.append(url)
        return _FakeRequestContext()

    retriever = _retriever(INTERNAL_URL)
    with (
        patch("aiohttp.ClientSession.get", new=fake_get),
        patch(
            "langchain_community.document_loaders.async_html.AsyncHtmlLoader._to_document",
            new=lambda self, url, text: Document(page_content=text, metadata={"source": url}),
        ),
        patch("langchain_community.retrievers.web_research.Html2TextTransformer", _IdentityHtmlTransformer),
    ):
        retriever.invoke("harmless query")

    assert sent_urls == [INTERNAL_URL]


class _SafeLoader:
    """Test adapter that routes loader URLs through SafeFetcher.

    This replaces only the loader boundary in the retriever. It demonstrates
    how SafeFetcher can guard this flow; it does not modify LangChain's stock
    AsyncHtmlLoader implementation.
    """

    fetcher: SafeFetcher

    def __init__(self, urls: list[str], **kwargs: Any) -> None:
        self.urls = urls

    def load(self) -> list[Document]:
        documents = []
        for url in self.urls:
            try:
                # SafeFetcher rejects loopback/private targets before _send is
                # reached. The retriever normally ignores a loader's fetch
                # failures and can continue with the remaining search results.
                result = self.fetcher.get(url)
            except Exception:
                # The vulnerable retriever asks its loader to ignore fetch errors.
                continue
            documents.append(
                Document(page_content=result.content.decode("utf-8"), metadata={"source": result.url})
            )
        return documents


def test_safe_egress_blocks_internal_search_result_in_real_retriever_flow() -> None:
    """The real retriever flow rejects a loopback result at the loader seam."""
    fetcher = SafeFetcher()
    _SafeLoader.fetcher = fetcher
    retriever = _retriever(INTERNAL_URL)
    with (
        patch("langchain_community.retrievers.web_research.AsyncHtmlLoader", _SafeLoader),
        patch("langchain_community.retrievers.web_research.Html2TextTransformer", _IdentityHtmlTransformer),
        patch.object(fetcher, "_send") as transport,
    ):
        retriever.invoke("harmless query")
    # No TCP transport call means the forbidden address was rejected in policy.
    transport.assert_not_called()


def test_safe_aiohttp_session_blocks_internal_search_result_before_connector() -> None:
    """The real loader can use the aiohttp adapter without opening a socket."""
    import aiohttp
    from unittest.mock import AsyncMock

    retriever = _retriever("http://127.0.0.1/internal-status")
    connector_attempt = AsyncMock()
    with (
        patch("langchain_community.retrievers.web_research.AsyncHtmlLoader", SafeWebResearchAsyncHtmlLoader),
        patch.object(aiohttp.TCPConnector, "_create_connection", new=connector_attempt),
        patch(
            "langchain_community.document_loaders.async_html.AsyncHtmlLoader._to_document",
            new=lambda self, url, text: Document(page_content=text, metadata={"source": url}),
        ),
        patch("langchain_community.retrievers.web_research.Html2TextTransformer", _IdentityHtmlTransformer),
    ):
        retriever.invoke("harmless query")

    connector_attempt.assert_not_awaited()


def test_safe_companion_loader_guards_its_requests_helper_too() -> None:
    """The loader's synchronous Requests helper cannot bypass its policy."""
    import requests

    loader = SafeWebResearchAsyncHtmlLoader(
        INTERNAL_URL,
        ignore_load_errors=False,
        policy=FetchPolicy(allowed_ports=frozenset({8080})),
    )
    fetcher = loader.session.get_adapter(INTERNAL_URL).fetcher
    with patch.object(fetcher, "_send") as transport:
        with pytest.raises(requests.ConnectionError):
            loader._fetch_valid_connection_docs(INTERNAL_URL)

    transport.assert_not_called()
    loader.session.close()


def test_safe_aiohttp_loader_preserves_public_fetch_in_retriever_flow() -> None:
    """The hardened loader fetches and indexes a public page via aiohttp."""
    store = _VectorStore()
    retriever = _retriever(PUBLIC_URL, store)
    public_ip = "93.184.216.34"
    body = b"<html><body>PUBLIC AIOHTTP FIXTURE CONTENT</body></html>"
    wire_response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: "
        + str(len(body)).encode("ascii")
        + b"\r\nConnection: close\r\n\r\n"
        + body
    )
    transports: list[_MemoryTransport] = []

    async def fake_getaddrinfo(
        loop: asyncio.AbstractEventLoop,
        host: str,
        port: int,
        *,
        family: int = socket.AF_UNSPEC,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[tuple[Any, ...]]:
        assert host == "example.com"
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (public_ip, port))]

    async def in_memory_connection(connector, factory, *args, **kwargs):
        loop = asyncio.get_running_loop()
        protocol = factory()
        transport = _MemoryTransport(loop, protocol, wire_response)
        transports.append(transport)
        protocol.connection_made(transport)
        return transport, protocol

    with (
        patch("langchain_community.retrievers.web_research.AsyncHtmlLoader", SafeWebResearchAsyncHtmlLoader),
        patch.object(asyncio.BaseEventLoop, "getaddrinfo", new=fake_getaddrinfo),
        patch.object(aiohttp.TCPConnector, "_wrap_create_connection", new=in_memory_connection),
        patch(
            "langchain_community.document_loaders.async_html.AsyncHtmlLoader._to_document",
            new=lambda self, url, text: Document(page_content=text, metadata={"source": url}),
        ),
        patch("langchain_community.retrievers.web_research.Html2TextTransformer", _IdentityHtmlTransformer),
    ):
        results = retriever.invoke("harmless query")

    assert transports
    assert store.documents
    assert results
    assert any("PUBLIC AIOHTTP FIXTURE CONTENT" in doc.page_content for doc in results)


def test_safe_egress_preserves_public_page_utility_in_real_retriever_flow() -> None:
    """A public destination remains fetchable and usable by the retriever.

    DNS and the final transport are simulated. The test checks the SafeFetcher
    policy path and the retriever's processing/indexing behavior without
    contacting example.com.
    """
    store = _VectorStore()
    fetcher = SafeFetcher()
    _SafeLoader.fetcher = fetcher
    public_ip = ipaddress.ip_address("93.184.216.34")
    # Pretend the public hostname resolves to a public IP; no DNS query occurs.
    records = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (str(public_ip), 443))]

    def simulated_fetch(
        target: Any,
        address: Any,
        headers: Any,
        *,
        method: str = "GET",
        body: bytes | None = None,
        timeout_seconds: float | None = None,
    ) -> FetchResponse:
        # This replaces the socket operation but still confirms the checked
        # address and original hostname reached the transport boundary.
        assert address == public_ip
        assert target.host == "example.com"
        return FetchResponse(
            status_code=200,
            headers=(("Content-Type", "text/html; charset=utf-8"),),
            content=b"<html><body>PUBLIC FIXTURE CONTENT</body></html>",
            url=target.url,
            history=(),
        )

    retriever = _retriever(PUBLIC_URL, store)
    with (
        patch("langchain_community.retrievers.web_research.AsyncHtmlLoader", _SafeLoader),
        patch("langchain_community.retrievers.web_research.Html2TextTransformer", _IdentityHtmlTransformer),
        patch("safe_egress.client.socket.getaddrinfo", return_value=records),
        patch.object(fetcher, "_send", side_effect=simulated_fetch),
    ):
        results = retriever.invoke("harmless query")

    assert store.documents
    assert results
    assert any("PUBLIC FIXTURE CONTENT" in doc.page_content for doc in results)
