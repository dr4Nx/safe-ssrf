"""Requests Session and transport adapter backed by ``SafeFetcher``."""

from __future__ import annotations

from contextvars import ContextVar
from datetime import timedelta
from io import BytesIO
import math
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

try:
    import requests
    from requests.adapters import BaseAdapter
except ImportError as exc:  # pragma: no cover - depends on optional extra
    raise ImportError("SafeRequestsSession requires the optional 'requests' dependency") from exc

from .client import SafeFetcher
from .errors import FetchError, PolicyError, RequestTooLargeError
from .policy import FetchPolicy, normalize_host

_REQUEST_POLICY: ContextVar[FetchPolicy | None] = ContextVar("safe_egress_requests_policy", default=None)


def _origin(url: str) -> tuple[str, str, int] | None:
    """Return the normalized HTTP origin, or None for a malformed URL."""
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or parsed.hostname is None:
            return None
        host = normalize_host(parsed.hostname)
        port = parsed.port if parsed.port is not None else (443 if scheme == "https" else 80)
        return scheme, host, port
    except (PolicyError, ValueError):
        return None


class SafeRequestsAdapter(BaseAdapter):
    """A Requests adapter that never delegates socket creation to Requests.

    Responses are buffered up to the active policy's size limit. Requests
    follows redirects and routes each hop back through this adapter, where
    SafeFetcher validates and pins the destination under the active policy.
    Streaming responses, proxy use, custom TLS verification settings, client
    certificates, and iterable upload bodies are rejected because this adapter
    does not implement those behaviors.
    """

    def __init__(self, fetcher: SafeFetcher | None = None, *, policy: FetchPolicy | None = None) -> None:
        super().__init__()
        if fetcher is not None and policy is not None:
            raise ValueError("Pass either fetcher or policy, not both")
        self.fetcher = fetcher or SafeFetcher(policy)

    def send(
        self,
        request: requests.PreparedRequest,
        stream: bool = False,
        timeout: Any = None,
        verify: bool | str = True,
        cert: Any = None,
        proxies: dict[str, str] | None = None,
    ) -> requests.Response:
        if stream:
            raise PolicyError("Streaming responses are unsupported by SafeRequestsAdapter")
        if proxies:
            raise PolicyError("Proxy configuration is unsupported by SafeRequestsAdapter")
        if verify is not True:
            raise PolicyError("Custom or disabled TLS verification is unsupported by SafeRequestsAdapter")
        if cert is not None:
            raise PolicyError("Client certificates are unsupported by SafeRequestsAdapter")

        body = self._request_body(request.body)
        headers = {
            name: value
            for name, value in request.headers.items()
            if name.lower() not in {"host", "content-length", "transfer-encoding"}
        }
        timeout_seconds = self._timeout_seconds(timeout)
        try:
            fetched = self.fetcher.request(
                request.method or "GET",
                request.url,
                headers=headers,
                body=body,
                timeout_seconds=timeout_seconds,
                follow_redirects=False,
                policy=_REQUEST_POLICY.get(),
            )
        except FetchError as exc:
            raise requests.ConnectionError(str(exc), request=request) from exc

        response = requests.Response()
        response.status_code = fetched.status_code
        response.headers = requests.structures.CaseInsensitiveDict(dict(fetched.headers))
        response._content = fetched.content
        response._content_consumed = True
        response.url = fetched.url
        response.encoding = requests.utils.get_encoding_from_headers(response.headers)
        response.request = requests.Request(
            fetched.method,
            fetched.url,
            headers=headers,
        ).prepare()
        response.history = []
        response.elapsed = timedelta(0)
        response.reason = ""
        response.raw = BytesIO(fetched.content)
        return response

    def close(self) -> None:
        return None

    def _request_body(self, body: Any) -> bytes | None:
        if body is None:
            return None
        active_policy = _REQUEST_POLICY.get() or self.fetcher.policy
        max_request_bytes = active_policy.max_request_bytes
        if isinstance(body, bytes):
            result = body
        elif isinstance(body, str):
            result = body.encode("utf-8")
        elif hasattr(body, "read"):
            result = body.read(max_request_bytes + 1)
            if isinstance(result, str):
                result = result.encode("utf-8")
            if not isinstance(result, bytes):
                raise PolicyError("File-like request body must produce bytes or text")
        else:
            raise PolicyError("Iterable request bodies are unsupported by SafeRequestsAdapter")
        if len(result) > max_request_bytes:
            raise RequestTooLargeError("Request body exceeded the configured byte limit")
        return result

    @staticmethod
    def _timeout_seconds(timeout: Any) -> float | None:
        if timeout is None:
            return None
        if isinstance(timeout, tuple) and len(timeout) != 2:
            raise PolicyError("Timeout pair must contain connect and read values")
        values = timeout if isinstance(timeout, tuple) else (timeout,)
        numeric = [value for value in values if value is not None]
        if not numeric or any(
            not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value <= 0
            for value in numeric
        ):
            raise PolicyError("Timeout must be a positive number or a (connect, read) pair")
        # The socket layer has one operation timeout. Taking the smaller
        # Requests timeout preserves a conservative bound for both phases.
        return min(numeric)


class SafeRequestsSession(requests.Session):
    """Requests Session with explicit safe adapters mounted for HTTP and HTTPS.

    This protects requests routed through this session. It does not alter the
    global ``requests.get`` function or other Sessions in the process. Its
    public ``mount`` method cannot replace the policy adapters with arbitrary
    transports.
    """

    def __init__(self, policy: FetchPolicy | None = None, *, fetcher: SafeFetcher | None = None) -> None:
        if policy is not None and fetcher is not None:
            raise ValueError("Pass either fetcher or policy, not both")
        self._safe_egress_locked = False
        self._safe_egress_adapters: dict[str, SafeRequestsAdapter] = {}
        super().__init__()
        self.trust_env = False
        adapter = SafeRequestsAdapter(fetcher=fetcher, policy=policy)
        self.max_redirects = adapter.fetcher.policy.max_redirects
        self._safe_egress_adapters = {"http://": adapter, "https://": adapter}
        self.mount("http://", adapter)
        self.mount("https://", adapter)
        # Requests exposes its adapter table as a mutable public attribute.
        # Freeze it after mounting so callers cannot bypass mount() by editing
        # the dictionary directly.
        self.adapters = MappingProxyType(self.adapters)
        self._safe_egress_locked = True

    def __setattr__(self, name: str, value: Any) -> None:
        """Prevent weakening the adapter table or redirect cap after setup."""
        if getattr(self, "_safe_egress_locked", False):
            if name == "adapters":
                raise PolicyError("SafeRequestsSession does not allow replacing its adapter table")
            if name == "max_redirects":
                raise PolicyError("SafeRequestsSession redirect limit is controlled by FetchPolicy")
        super().__setattr__(name, value)

    def mount(self, prefix: str, adapter: BaseAdapter) -> None:
        """Keep Requests' routing APIs from replacing the safe transports."""
        if getattr(self, "_safe_egress_locked", False):
            if self._safe_egress_adapters.get(prefix) is adapter:
                return
            raise PolicyError("SafeRequestsSession does not allow custom transport mounts")
        super().mount(prefix, adapter)

    def request(
        self,
        method: str,
        url: str,
        *args: Any,
        policy: FetchPolicy | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Send a request using the session policy or an explicit per-call policy.

        The selected policy remains active while Requests follows redirects, so
        every redirected request is checked under the same policy. The context
        variable keeps concurrent threads using one session from sharing policy
        overrides.
        """
        if policy is not None and not isinstance(policy, FetchPolicy):
            raise PolicyError("policy must be a FetchPolicy")
        if policy is not None and policy.max_redirects != self.max_redirects:
            raise PolicyError(
                "A per-request policy must use the session's configured redirect limit"
            )
        token = _REQUEST_POLICY.set(policy)
        try:
            return super().request(method, url, *args, **kwargs)
        finally:
            _REQUEST_POLICY.reset(token)

    def rebuild_auth(self, prepared_request: requests.PreparedRequest, response: requests.Response) -> None:
        """Drop sensitive headers when Requests builds a cross-origin redirect."""
        old_url = response.request.url if response.request is not None else response.url
        if old_url is not None and _origin(old_url) != _origin(prepared_request.url):
            for name in ("Authorization", "Cookie", "Origin"):
                prepared_request.headers.pop(name, None)
        super().rebuild_auth(prepared_request, response)
