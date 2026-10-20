"""Small, explicit adapters for existing Python HTTP-client call sites."""

from __future__ import annotations

from datetime import timedelta
from typing import Mapping

from .client import SafeFetcher


class RequestsGet:
    """Requests-compatible ``GET`` facade backed by :class:`SafeFetcher`.

    This is intentionally not a ``requests.Session`` or transport adapter. It
    supports only ``get(url, headers=...)`` and never delegates network access
    to Requests. Install the optional ``requests`` dependency to use it.
    """

    def __init__(self, fetcher: SafeFetcher | None = None) -> None:
        self.fetcher = fetcher or SafeFetcher()

    def get(self, url: str, *, headers: Mapping[str, str] | None = None):
        try:
            from requests import Request, Response
            from requests.structures import CaseInsensitiveDict
            from requests.utils import get_encoding_from_headers
        except ImportError as exc:
            raise ImportError("RequestsGet requires the optional 'requests' dependency") from exc

        fetched = self.fetcher.get(url, headers=headers)
        result = Response()
        result.status_code = fetched.status_code
        result.headers = CaseInsensitiveDict(dict(fetched.headers))
        result._content = fetched.content
        result._content_consumed = True
        result.url = fetched.url
        result.encoding = get_encoding_from_headers(result.headers)
        result.request = Request("GET", fetched.url, headers=headers).prepare()
        result.history = []
        result.elapsed = timedelta(0)
        return result
