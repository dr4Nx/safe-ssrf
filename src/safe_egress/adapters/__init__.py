"""HTTP client integrations.

Each backend lives in its own module. Shared policy, validation, and transport
logic lives in the parent :mod:`safe_egress` package.

Modules are not imported here so each adapter's optional dependency stays
optional.
"""
