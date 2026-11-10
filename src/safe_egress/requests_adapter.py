"""Backward-compatible alias; implementation lives in :mod:`adapters.requests`."""

import sys as _sys

from .adapters import requests as _implementation

_sys.modules[__name__] = _implementation
