#!/usr/bin/env python3
"""Run Kolibri's hardened Requests integration against an installed wheel."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import unittest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", type=Path, required=True)
    parser.add_argument("--expected-site", type=Path, required=True)
    args = parser.parse_args()

    # Load Safe Egress before importing the benchmark. Its source harness adds
    # the checkout's src/ directory to sys.path; this check prevents that path
    # from silently replacing the installed package under evaluation.
    import safe_egress

    package_path = Path(safe_egress.__file__).resolve()
    expected_site = args.expected_site.resolve()
    if not package_path.is_relative_to(expected_site):
        parser.error(f"safe_egress imported from {package_path}, outside {expected_site}")

    benchmark = args.benchmark.resolve()
    sys.path.insert(0, str(benchmark))
    from grader.test_ssrf_behavior import KolibriSafeEgressIntegrationTests

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(KolibriSafeEgressIntegrationTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
