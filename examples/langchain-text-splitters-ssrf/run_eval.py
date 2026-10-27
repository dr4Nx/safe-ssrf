#!/usr/bin/env python3
"""Evaluate pinned LangChain Text Splitters revisions with local SSRF fixtures."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from datetime import datetime, timezone


CASE_DIR = Path(__file__).resolve().parent
ROOT = CASE_DIR.parents[1]
DEFAULT_VULNERABLE = ROOT.parent / "langchain-text-splitters-vuln"
DEFAULT_FIXED = ROOT.parent / "langchain-text-splitters-fixed-1.1.2"


def git_revision(repo: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    ).stdout.strip()


def run_phase(name: str, command: list[str], cwd: Path, env: dict[str, str], output: Path) -> dict:
    started = time.monotonic()
    try:
        result = subprocess.run(
            command, cwd=cwd, env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        )
        log_text, code = result.stdout, result.returncode
    except OSError as exc:
        log_text, code = f"{type(exc).__name__}: {exc}\n", 127
    elapsed = round(time.monotonic() - started, 3)
    log_path = output / f"{name}.log"
    log_path.write_text(log_text, encoding="utf-8")
    return {
        "command": command,
        "cwd": str(cwd),
        "exit_code": code,
        "status": "passed" if code == 0 else "failed_or_blocked",
        "elapsed_seconds": elapsed,
        "log": str(log_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vulnerable-repo", type=Path, default=DEFAULT_VULNERABLE)
    parser.add_argument("--fixed-repo", type=Path, default=DEFAULT_FIXED)
    parser.add_argument(
        "--output-dir", type=Path,
        default=CASE_DIR / "results" / "latest",
    )
    args = parser.parse_args()
    vulnerable = args.vulnerable_repo.resolve()
    fixed = args.fixed_repo.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PIP_NO_INDEX"] = "1"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["LANGCHAIN_SPLITTERS_VULNERABLE"] = str(vulnerable)
    env["LANGCHAIN_SPLITTERS_FIXED"] = str(fixed)
    env["PYTHONPATH"] = os.pathsep.join(
        item for item in (str(ROOT / "src"), env.get("PYTHONPATH", "")) if item
    )

    phases = {}
    for label, repo in (("vulnerable", vulnerable), ("fixed", fixed)):
        package = repo / "libs/text-splitters"
        wheel_dir = output / "wheels" / label
        wheel_dir.mkdir(parents=True, exist_ok=True)
        phases[f"{label}_build"] = run_phase(
            f"{label}_build",
            [
                sys.executable, "-m", "pip", "wheel", "--no-deps",
                "--no-build-isolation", "--wheel-dir", str(wheel_dir), str(package),
            ],
            ROOT,
            env,
            output,
        )

        test_env = dict(env)
        test_env["PYTHONPATH"] = os.pathsep.join(
            (str(repo / "libs/core"), str(package), str(ROOT / "src"), env.get("PYTHONPATH", ""))
        )
        phases[f"{label}_existing_tests"] = run_phase(
            f"{label}_existing_tests",
            [sys.executable, "-m", "pytest", "-q", "tests/unit_tests/test_text_splitters.py"],
            package,
            test_env,
            output,
        )

    phases["ssrf_and_utility_fixtures"] = run_phase(
        "ssrf_and_utility_fixtures",
        [sys.executable, "-m", "unittest", "discover", "-s", str(CASE_DIR), "-p", "test_*.py", "-v"],
        ROOT,
        env,
        output,
    )

    report = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version,
        "revisions": {
            "vulnerable": {"tag": "langchain-text-splitters==1.1.1", "commit": git_revision(vulnerable), "path": str(vulnerable)},
            "fixed": {"tag": "langchain-text-splitters==1.1.2", "commit": git_revision(fixed), "path": str(fixed)},
        },
        "fixture_network": "synthetic DNS and in-memory Requests/HTTPX responses; no sockets or external services",
        "phases": phases,
        "execution_time_seconds": round(sum(phase["elapsed_seconds"] for phase in phases.values()), 3),
    }
    (output / "evaluation.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
