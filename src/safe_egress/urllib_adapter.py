"""Backward-compatible alias; implementation lives in :mod:`adapters.urllib`."""

import sys as _sys

from .adapters import urllib as _implementation

_sys.modules[__name__] = _implementation
