"""Experimental AsyncHtmlLoader integration using Safe Egress aiohttp policy.

This class is kept beside the benchmark instead of modifying the LangChain
checkout. It preserves the loader's HTML parsing and retry behavior while
replacing its aiohttp session construction. It is a focused example, not a
maintained LangChain fork.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import aiohttp
from langchain_community.document_loaders.async_html import AsyncHtmlLoader

from safe_egress import FetchPolicy, PolicyError
from safe_egress.adapters.aiohttp import safe_aiohttp_session
from safe_egress.adapters.requests import SafeRequestsSession

logger = logging.getLogger(__name__)


class SafeAsyncHtmlLoader(AsyncHtmlLoader):
    """One-line fetch-boundary replacement."""

    safe_policy = FetchPolicy()

    async def _fetch(
        self, url: str, retries: int = 3, cooldown: int = 2, backoff: float = 1.5
    ) -> str:
        async with safe_aiohttp_session(policy=self.safe_policy) as session:
            for i in range(retries):
                try:
                    async with session.get(
                        url,
                        headers=self.session.headers,
                        ssl=None if self.session.verify else False,
                        **self.requests_kwargs,
                    ) as response:
                        try:
                            text = await response.text()
                        except UnicodeDecodeError:
                            logger.error(f"Failed to decode content from {url}")
                            text = ""
                        return text
                except (aiohttp.ClientConnectionError, TimeoutError) as exc:
                    if i == retries - 1 and self.ignore_load_errors:
                        logger.warning(f"Error fetching {url} after {retries} retries.")
                        return ""
                    elif i == retries - 1:
                        raise
                    else:
                        logger.warning(
                            f"Error fetching {url} with attempt "
                            f"{i + 1}/{retries}: {exc}. Retrying..."
                        )
                        await asyncio.sleep(cooldown * backoff**i)
        raise ValueError("retry count exceeded")


class SafeWebResearchAsyncHtmlLoader(AsyncHtmlLoader):
    """AsyncHtmlLoader whose URL fetches use the safe aiohttp session."""

    def __init__(self, *args: Any, policy: FetchPolicy | None = None, **kwargs: Any) -> None:
        if kwargs.get("proxies"):
            raise PolicyError("SafeWebResearchAsyncHtmlLoader does not support proxies")
        kwargs["proxies"] = None
        kwargs["trust_env"] = False
        selected_policy = policy or FetchPolicy()
        super().__init__(*args, **kwargs)
        previous_session = self.session
        safe_session = SafeRequestsSession(policy=selected_policy)
        safe_session.headers = dict(previous_session.headers)
        safe_session.verify = previous_session.verify
        previous_session.close()
        self.session = safe_session
        self.safe_policy = selected_policy

    async def _fetch(
        self, url: str, retries: int = 3, cooldown: int = 2, backoff: float = 1.5
    ) -> str:
        async with safe_aiohttp_session(policy=self.safe_policy) as session:
            for attempt in range(retries):
                try:
                    async with session.get(
                        url,
                        headers=self.session.headers,
                        ssl=None if self.session.verify else False,
                        **self.requests_kwargs,
                    ) as response:
                        try:
                            return await response.text()
                        except UnicodeDecodeError:
                            logger.error("Failed to decode content from %s", url)
                            return ""
                except PolicyError:
                    if self.ignore_load_errors:
                        logger.warning("Safe Egress rejected destination %s", url)
                        return ""
                    raise
                except (aiohttp.ClientConnectionError, TimeoutError) as exc:
                    if attempt == retries - 1 and self.ignore_load_errors:
                        logger.warning("Error fetching %s after %s retries: %s", url, retries, exc)
                        return ""
                    if attempt == retries - 1:
                        raise
                    logger.warning(
                        "Error fetching %s with attempt %s/%s: %s",
                        url,
                        attempt + 1,
                        retries,
                        exc,
                    )
                    await asyncio.sleep(cooldown * backoff**attempt)
        raise ValueError("retry count exceeded")
