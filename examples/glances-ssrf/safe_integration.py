"""Safe outbound helper for Glances' configured public-IP endpoint.

This companion is intentionally small so an application can review the
security decision and request behavior without patching urllib globally.
"""

from __future__ import annotations

import base64
import json
from typing import Any
from urllib.request import Request
from urllib.parse import urlsplit

from safe_egress import FetchPolicy
from safe_egress.urllib_adapter import SafeUrllibOpener


class SafePublicIpFetcher:
    """Fetch the configured JSON endpoint through Safe Egress.

    ``allowed_hosts`` must come from trusted application configuration, not
    from the URL being fetched. The exact-host policy limits where optional
    Basic credentials can be sent as well as blocking private IP addresses.
    The helper also requires HTTPS to protect those credentials in transit.
    """

    def __init__(self, *, policy: FetchPolicy) -> None:
        if not isinstance(policy, FetchPolicy):
            raise TypeError("policy must be a FetchPolicy")
        if not policy.allowed_hosts:
            raise ValueError("A trusted exact-host allowlist is required for this credentialed fetch")
        if policy.allowed_ips:
            raise ValueError("Private or special-use IP exceptions are not allowed for the public-IP endpoint")
        if policy.allowed_ports != frozenset({443}):
            raise ValueError("The credentialed public-IP endpoint is restricted to HTTPS port 443")
        self.opener = SafeUrllibOpener(policy=policy)

    def fetch(self, url: str, *, username: str | None, password: str | None, timeout: float) -> Any:
        """Return parsed JSON or ``None`` on transport, policy, or parse errors.

        This preserves Glances' existing background worker behavior, which
        treats an unavailable public-IP service as missing information.
        """
        headers: dict[str, str] = {}
        if username and password:
            raw_credentials = f"{username}:{password}".encode()
            token = base64.b64encode(raw_credentials).decode("ascii")
            headers["Authorization"] = f"Basic {token}"

        try:
            # The configured endpoint can receive Basic credentials. HTTPS is
            # required even for an allowlisted host to prevent credential
            # exposure from a plain-HTTP configuration or downgrade.
            if urlsplit(url).scheme.lower() != "https":
                return None
            # SafeUrllibOpener validates the URL and resolves/pins the peer
            # before sending this request. It also rechecks every redirect.
            with self.opener.open(Request(url, headers=headers), timeout=timeout) as response:
                return json.loads(response.read())
        except Exception:
            return None


def make_safe_thread_class(base_thread: type, fetcher: SafePublicIpFetcher) -> type:
    """Wrap Glances' thread class while retaining its API and scheduler.

    Replace the imported ``ThreadPublicIpAddress`` with the returned class.
    Only the fetch method changes; Glances continues to own the thread loop,
    refresh timing, and result synchronization.
    """

    class SafeThreadPublicIpAddress(base_thread):
        def _fetch_public_ip_info(self):
            return fetcher.fetch(
                self.url,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
            )

    SafeThreadPublicIpAddress.__name__ = "SafeThreadPublicIpAddress"
    return SafeThreadPublicIpAddress
