"""Backward-compatible alias; implementation lives in :mod:`adapters.urllib3_compat`."""

import sys as _sys

from .adapters import urllib3_compat as _implementation

_sys.modules[__name__] = _implementation
