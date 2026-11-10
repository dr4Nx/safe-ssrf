"""Local vulnerable counterpart for the LangChain loader demonstration."""

from __future__ import annotations

import asyncio
import logging

import aiohttp
from langchain_community.document_loaders.async_html import AsyncHtmlLoader


logger = logging.getLogger(__name__)


class VulnerableAsyncHtmlLoader(AsyncHtmlLoader):
    """Demonstration copy of the vulnerable 0.2.7 async fetch method."""

    async def _fetch(
        self, url: str, retries: int = 3, cooldown: int = 2, backoff: float = 1.5
    ) -> str:
        async with aiohttp.ClientSession(trust_env=self.trust_env) as session:
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
                except (aiohttp.ClientConnectionError, TimeoutError) as e:
                    if i == retries - 1 and self.ignore_load_errors:
                        logger.warning(f"Error fetching {url} after {retries} retries.")
                        return ""
                    elif i == retries - 1:
                        raise
                    else:
                        logger.warning(
                            f"Error fetching {url} with attempt "
                            f"{i + 1}/{retries}: {e}. Retrying..."
                        )
                        await asyncio.sleep(cooldown * backoff**i)
        raise ValueError("retry count exceeded")
