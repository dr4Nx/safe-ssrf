"""Backward-compatible alias; implementation lives in :mod:`adapters.requests_compat`."""

import sys as _sys

from .adapters import requests_compat as _implementation

_sys.modules[__name__] = _implementation
