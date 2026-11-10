"""Backward-compatible import path; implementation lives in adapters.curl_cffi."""

# Keep legacy monkeypatch paths aimed at the implementation module too.
import sys as _sys

from .adapters import curl_cffi as _implementation

_sys.modules[__name__] = _implementation
