"""Print a safe, direct comparison of the vulnerable and guarded loaders.

Run with the LangChain Community Poetry environment and source paths described
in this example's README. The vulnerable call is intercepted in memory; the
guarded call is stopped by policy before aiohttp opens a connection.
"""

from __future__ import annotations

import os
import textwrap
from typing import Any
from unittest.mock import AsyncMock, patch
import warnings

os.environ.setdefault("USER_AGENT", "safe-egress-local-demo")
warnings.filterwarnings("ignore", message="For better logging of progress.*")

import aiohttp
from langchain_core.documents import Document
from langchain_community.document_loaders.async_html import AsyncHtmlLoader

from hardened_async_html import SafeAsyncHtmlLoader
from vulnerable_async_html import VulnerableAsyncHtmlLoader


INTERNAL_URL = "http://127.0.0.1/internal-status"
DUMMY_HTML = "<html><body>SIMULATED INTERNAL SERVICE: dummy data</body></html>"


def _to_document(_loader: Any, url: str, text: str) -> Document:
    """Avoid making the demo depend on the unrelated BeautifulSoup parser."""
    return Document(page_content=text, metadata={"source": url})


class _FakeResponse:
    async def text(self) -> str:
        return DUMMY_HTML


class _FakeRequest:
    async def __aenter__(self) -> _FakeResponse:
        return _FakeResponse()

    async def __aexit__(self, *args: Any) -> None:
        return None


def main() -> None:
    vulnerable_loader = VulnerableAsyncHtmlLoader(
        INTERNAL_URL,
        requests_per_second=1,
        trust_env=False,
    )
    sent_urls: list[str] = []

    def fake_get(_session: Any, url: str, **kwargs: Any) -> _FakeRequest:
        sent_urls.append(url)
        return _FakeRequest()

    try:
        # This captures the exact URL at aiohttp's request boundary. No socket opens.
        with (
            patch.object(aiohttp.ClientSession, "get", new=fake_get),
            patch.object(AsyncHtmlLoader, "_to_document", new=_to_document),
        ):
            documents = vulnerable_loader.load()
        vulnerable_result = documents[0].page_content
    finally:
        vulnerable_loader.session.close()

    safe_loader = SafeAsyncHtmlLoader(
        INTERNAL_URL,
        requests_per_second=1,
        ignore_load_errors=False,
    )
    connector_attempt = AsyncMock()
    safe_result = ""
    connector_opened = False
    try:
        with (
            patch.object(aiohttp.TCPConnector, "_create_connection", new=connector_attempt),
            patch.object(AsyncHtmlLoader, "_to_document", new=_to_document),
        ):
            try:
                safe_loader.load()
            except Exception as exc:
                safe_result = textwrap.shorten(
                    f"rejected: {type(exc).__name__}: {exc}", width=48, placeholder="..."
                )
            else:
                raise AssertionError("the safe loader unexpectedly fetched a loopback URL")
        connector_opened = connector_attempt.await_count > 0
    finally:
        safe_loader.session.close()

    print("LangChain AsyncHtmlLoader comparison (local fixtures)")
    print(f"{'':24} | {'VULNERABLE 0.2.7':48} | {'SAFE EGRESS':48}")
    print("-" * 127)
    print(f"{'URL':24} | {sent_urls[0]:48} | {INTERNAL_URL:48}")
    print(
        f"{'Outcome':24} | {'returned dummy internal content':48} | "
        f"{safe_result:48}"
    )
    print(
        f"{'Network boundary':24} | {'aiohttp.get intercepted; no socket':48} | "
        f"{f'connector opened: {connector_opened}':48}"
    )
    body_summary = (
        "SIMULATED INTERNAL SERVICE: dummy data"
        if "SIMULATED INTERNAL SERVICE" in vulnerable_result
        else textwrap.shorten(vulnerable_result, width=48, placeholder="...")
    )
    print(f"{'Returned content':24} | {body_summary:48} | {'(blocked before response)':48}")


if __name__ == "__main__":
    main()
