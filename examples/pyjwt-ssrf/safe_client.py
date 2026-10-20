"""PyJWKClient integration using Safe Egress for outbound JWKS requests.

This is an application integration example. PyJWT does not expose a transport
injection point, so applications that want destination checks can subclass
PyJWKClient and route its fetch_data operation through SafeUrllibOpener.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError

from safe_egress.policy import FetchPolicy
from safe_egress.urllib_adapter import SafeUrllibOpener


class SafePyJWKClient(PyJWKClient):
    """PyJWKClient variant whose configured URL is checked at every hop."""

    def __init__(self, uri: str, *, policy: FetchPolicy | None = None, **kwargs: Any) -> None:
        super().__init__(uri, **kwargs)
        self._safe_opener = SafeUrllibOpener(policy=policy)

    def fetch_data(self) -> Any:
        request = urllib.request.Request(url=self.uri, headers=self.headers)
        try:
            with self._safe_opener.open(request, timeout=self.timeout) as response:
                jwk_set = json.load(response)
        except (urllib.error.URLError, TimeoutError) as exc:
            if isinstance(exc, urllib.error.HTTPError):
                exc.close()
            raise PyJWKClientConnectionError(
                f'Fail to fetch data from the url, err: "{exc}"'
            ) from exc
        if self.jwk_set_cache is not None:
            self.jwk_set_cache.put(jwk_set)
        return jwk_set
