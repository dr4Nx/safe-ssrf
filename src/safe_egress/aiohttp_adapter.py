"""Backward-compatible alias; implementation lives in :mod:`adapters.aiohttp`."""

import sys as _sys

from .adapters import aiohttp as _implementation

_sys.modules[__name__] = _implementation
