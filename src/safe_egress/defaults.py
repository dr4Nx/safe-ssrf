"""Default policy shared by the Safe Egress clients."""

from .policy import FetchPolicy


# Immutable baseline: public unicast destinations on ports 80 and 443 only.
DEFAULT_POLICY = FetchPolicy()

__all__ = ["DEFAULT_POLICY"]
