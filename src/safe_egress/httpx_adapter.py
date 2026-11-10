"""Backward-compatible alias; implementation lives in :mod:`adapters.httpx`."""

import sys as _sys

from .adapters import httpx as _implementation

_sys.modules[__name__] = _implementation
