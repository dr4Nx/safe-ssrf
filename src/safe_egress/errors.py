"""Exceptions raised by :mod:`safe_egress`."""


class FetchError(Exception):
    """A request could not be completed safely or successfully."""


class PolicyError(FetchError):
    """A URL, destination, or redirect violates the active fetch policy."""


class RedirectLimitError(FetchError):
    """The server returned more redirects than the policy allows."""


class ResponseTooLargeError(FetchError):
    """The response body exceeded the configured byte limit."""


class RequestTooLargeError(FetchError):
    """The request body exceeded the configured byte limit."""
