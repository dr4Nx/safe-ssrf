#!/usr/bin/env python3
"""Evaluate PyJWT source revisions and local SSRF fixtures without installs."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


CASE_DIR = Path(__file__).resolve().parent
ROOT = CASE_DIR.parents[1]
REPRODUCER = CASE_DIR / "reproduce.py"
UPSTREAM_TEST = Path("tests/test_jwks_client.py")
LOCAL_SERVER_TEST = "test_fetch_data_rejects_redirect_without_contacting_destination"


def revision(repo: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    )
    return result.stdout.strip()


def run_phase(name: str, command: list[str], cwd: Path, env: dict[str, str], out: Path) -> dict:
    started = time.monotonic()
    try:
        result = subprocess.run(
            command, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        )
        output, code = result.stdout, result.returncode
    except OSError as exc:
        output, code = f"{type(exc).__name__}: {exc}\n", 127
    elapsed = round(time.monotonic() - started, 3)
    out.mkdir(parents=True, exist_ok=True)
    log = out / f"{name}.log"
    log.write_text(output, encoding="utf-8")
    return {
        "command": command,
        "exit_code": code,
        "status": "passed" if code == 0 else "failed_or_blocked",
        "duration_seconds": elapsed,
        "log": str(log),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vulnerable-redirect", type=Path, required=True)
    parser.add_argument("--vulnerable-scheme", type=Path, required=True)
    parser.add_argument("--fixed-redirect", type=Path, required=True)
    parser.add_argument("--fixed-scheme", type=Path, required=True)
    parser.add_argument(
        "--current-upstream",
        type=Path,
        help="Optional current PyJWT checkout for behavior-only fixed controls",
    )
    parser.add_argument("--output-dir", type=Path, default=CASE_DIR / "results")
    args = parser.parse_args()

    repos = {
        "vulnerable_redirect": args.vulnerable_redirect.resolve(),
        "vulnerable_scheme": args.vulnerable_scheme.resolve(),
        "fixed_redirect": args.fixed_redirect.resolve(),
        "fixed_scheme": args.fixed_scheme.resolve(),
    }
    if args.current_upstream is not None:
        repos["current_upstream"] = args.current_upstream.resolve()
    out = args.output_dir.resolve()
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(ROOT / "src"), env.get("PYTHONPATH", "")) if part
    )
    phases = {}

    vulnerable_tests = [sys.executable, "-m", "pytest", "-q", str(UPSTREAM_TEST)]
    fixed_tests = [
        *vulnerable_tests,
        "-k",
        f"not {LOCAL_SERVER_TEST}",
    ]
    phases["vulnerable_redirect_existing_tests"] = run_phase(
        "vulnerable_redirect_existing_tests", vulnerable_tests,
        repos["vulnerable_redirect"], env, out,
    )
    phases["fixed_redirect_existing_tests"] = run_phase(
        "fixed_redirect_existing_tests", fixed_tests,
        repos["fixed_redirect"], env, out,
    )

    case_specs = [
        ("redirect_vulnerable", "vulnerable_redirect", "vulnerable"),
        ("redirect_fixed", "fixed_redirect", "fixed"),
        ("redirect_hardened", "vulnerable_redirect", "hardened"),
        ("scheme_vulnerable", "vulnerable_scheme", "vulnerable-scheme"),
        ("scheme_fixed", "fixed_scheme", "fixed-scheme"),
        ("scheme_hardened", "vulnerable_scheme", "hardened-scheme"),
    ]
    if args.current_upstream is not None:
        case_specs.extend(
            (
                ("current_upstream_redirect", "current_upstream", "fixed-current"),
                ("current_upstream_scheme", "current_upstream", "fixed-current-scheme"),
            )
        )
    for name, repo_key, mode in case_specs:
        phases[name] = run_phase(
            name,
            [sys.executable, str(REPRODUCER), "--repo", str(repos[repo_key]), "--mode", mode],
            repos[repo_key], env, out,
        )

    report = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version,
        "revisions": {name: {"path": str(repo), "commit": revision(repo)} for name, repo in repos.items()},
        "fixture_network": "in-memory HTTP, synthetic loopback, and a temporary dummy file only",
        "phases": phases,
        "execution_time_seconds": round(sum(p["duration_seconds"] for p in phases.values()), 3),
    }
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / "evaluation-python311.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if all(p["exit_code"] == 0 for p in phases.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
