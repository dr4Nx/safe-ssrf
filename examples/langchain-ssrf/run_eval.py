#!/usr/bin/env python3
"""Run the local LangChain SSRF, utility, source, and release checks."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GRADER = Path(__file__).resolve().parent
CHECK_RELEASE = GRADER / "check_release_default.py"
INTEGRATION_TEST = GRADER / "test_web_research_integration.py"
EXISTING_TEST = Path("tests/unit_tests/retrievers/test_web_research.py")


def source_root(repo: Path) -> Path:
    community = repo / "libs" / "community"
    return community if community.is_dir() else repo


def revision(repo: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    )
    return result.stdout.strip()


def run_phase(name: str, command: list[str], cwd: Path, env: dict[str, str], logs: Path) -> dict:
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
    path = logs / f"{name}.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(output, encoding="utf-8")
    return {
        "command": command,
        "exit_code": code,
        "status": "passed" if code == 0 else "failed_or_blocked",
        "duration_seconds": elapsed,
        "log": str(path),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vulnerable", type=Path, required=True)
    parser.add_argument("--fixed", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=GRADER / "results")
    args = parser.parse_args()

    vulnerable, fixed = args.vulnerable.resolve(), args.fixed.resolve()
    vulnerable_community, fixed_community = source_root(vulnerable), source_root(fixed)
    logs = args.output_dir.resolve()
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    safe_paths = [str(ROOT / "src"), str(GRADER)]

    def source_env(repo_source: Path) -> dict[str, str]:
        result = dict(env)
        paths = [str(repo_source), *safe_paths]
        if result.get("PYTHONPATH"):
            paths.append(result["PYTHONPATH"])
        result["PYTHONPATH"] = os.pathsep.join(paths)
        return result

    phases = {}
    for label, repo, community in (
        ("vulnerable", vulnerable, vulnerable_community),
        ("fixed", fixed, fixed_community),
    ):
        build_env = dict(env)
        build_env["POETRY_VIRTUALENVS_CREATE"] = "false"
        phases[f"{label}_build"] = run_phase(
            f"{label}_build",
            ["poetry", "build", "--format", "wheel", "--output", f"/tmp/safe-egress-langchain-{label}-wheel"],
            community, build_env, logs,
        )
        phases[f"{label}_existing_tests"] = run_phase(
            f"{label}_existing_tests",
            [sys.executable, "-m", "pytest", "-q", str(EXISTING_TEST)],
            community, source_env(community), logs,
        )
        phases[f"{label}_release_default"] = run_phase(
            f"{label}_release_default",
            [sys.executable, str(CHECK_RELEASE)],
            community, source_env(community), logs,
        )

    phases["ssrf_and_utility_integration"] = run_phase(
        "ssrf_and_utility_integration",
        [sys.executable, "-m", "pytest", "-q", str(INTEGRATION_TEST)],
        vulnerable_community, source_env(vulnerable_community), logs,
    )
    phases["ssrf_and_utility_integration_fixed_source"] = run_phase(
        "ssrf_and_utility_integration_fixed_source",
        [sys.executable, "-m", "pytest", "-q", str(INTEGRATION_TEST)],
        fixed_community, source_env(fixed_community), logs,
    )

    report = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version,
        "vulnerable_repository": str(vulnerable),
        "vulnerable_revision": revision(vulnerable),
        "fixed_repository": str(fixed),
        "fixed_revision": revision(fixed),
        "fixture_network": "in-memory responses and synthetic DNS; no sockets or external services",
        "phases": phases,
        "execution_time_seconds": round(sum(p["duration_seconds"] for p in phases.values()), 3),
    }
    report_path = logs / "evaluation.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if all(p["exit_code"] == 0 for p in phases.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
