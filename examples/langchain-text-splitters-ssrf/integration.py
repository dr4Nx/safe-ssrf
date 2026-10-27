"""Safe Egress client factory for LangChain's SSRF-safe client call site."""

from __future__ import annotations

from typing import Any

from safe_egress import FetchPolicy
from safe_egress.httpx_adapter import SafeClient


def ssrf_safe_client(**kwargs: Any) -> SafeClient:
    """Return the sync client expected by LangChain's transport factory API.

    This integration intentionally uses Safe Egress' public-only default
    policy. Callers that need private resources should define an explicit
    exact-IP policy in trusted application configuration.
    """
    if kwargs:
        raise ValueError("The Safe Egress client factory does not accept routing overrides")
    return SafeClient(policy=FetchPolicy(), follow_redirects=True)
