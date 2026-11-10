"""Backward-compatible alias; implementation lives in :mod:`adapters.urllib3`."""

import sys as _sys

from .adapters import urllib3 as _implementation

_sys.modules[__name__] = _implementation
