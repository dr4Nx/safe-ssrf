"""Policy-driven outbound HTTP fetching."""

from .client import FetchResponse, SafeFetcher, ValidatedDestination
from .adapters.curl_cffi import SafeCurlCffiSession
from .defaults import DEFAULT_POLICY
from .errors import (
    FetchError,
    PolicyError,
    RedirectLimitError,
    RequestTooLargeError,
    ResponseTooLargeError,
)
from .integrations import RequestsGet
from .policy import FetchPolicy

__all__ = [
    "DEFAULT_POLICY",
    "FetchError",
    "FetchPolicy",
    "FetchResponse",
    "PolicyError",
    "RedirectLimitError",
    "RequestTooLargeError",
    "ResponseTooLargeError",
    "RequestsGet",
    "SafeFetcher",
    "SafeCurlCffiSession",
    "ValidatedDestination",
]
