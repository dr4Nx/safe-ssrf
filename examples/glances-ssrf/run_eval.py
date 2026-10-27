#!/usr/bin/env python3
"""Build and evaluate the Glances SSRF case using only local source and fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from datetime import datetime, timezone


CASE_DIR = Path(__file__).resolve().parent
ROOT = CASE_DIR.parents[1]
DEFAULT_VULNERABLE = ROOT.parent / "glances-v4.5.3"
DEFAULT_FIXED = ROOT.parent / "glances-v4.5.4"
IP_TEST = "test_core.TestGlances.test_012_ip"
SOURCE_FILES = (
    "glances/plugins/ip/__init__.py",
    "glances/globals.py",
)
EXPECTED_SOURCE_FILE_SHA256 = {
    "v4.5.3": {
        "glances/plugins/ip/__init__.py": "ed61ba3431e4d01ad1b494687b4f935853e87bb34f025fe42bedf006dd9173b1",
        "glances/globals.py": "cdf37170fb339626dc5e719ac0c267f26b092f2b8a4c0f8d268661e6a559093b",
    },
    "v4.5.4": {
        "glances/plugins/ip/__init__.py": "3fa950f8144d33add21324a0954bb6927fa7efc3d07444d94f9c79c378c1c5b3",
        "glances/globals.py": "cdf37170fb339626dc5e719ac0c267f26b092f2b8a4c0f8d268661e6a559093b",
    },
}
ARCHIVE_SHA256 = {
    "v4.5.3": "e5169d273e40740b9b13626fd566239050e36169cf678ae82329ccf0300e1767",
    "v4.5.4": "a4f421c608d6c40e926c0256f915f0e820d92e5837e6b5a9eea582cf9b241c4a",
}


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_phase(name: str, command: list[str], cwd: Path, env: dict[str, str], output_dir: Path) -> dict:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        output = completed.stdout
        exit_code = completed.returncode
    except OSError as exc:
        output = f"{type(exc).__name__}: {exc}\n"
        exit_code = 127
    elapsed = round(time.monotonic() - started, 3)
    output_dir.mkdir(parents=True, exist_ok=True)
    log_path = output_dir / f"{name}.log"
    log_path.write_text(output, encoding="utf-8")
    return {
        "command": command,
        "cwd": str(cwd),
        "exit_code": exit_code,
        "status": "passed" if exit_code == 0 else "failed_or_blocked",
        "elapsed_seconds": elapsed,
        "log": str(log_path),
    }


def revision_record(repo: Path, tag: str) -> dict:
    actual_source_hashes = {
        name: file_sha256(repo / name)
        for name in SOURCE_FILES
    }
    expected_source_hashes = EXPECTED_SOURCE_FILE_SHA256[tag]
    return {
        "tag": tag,
        "path": str(repo),
        "expected_source_archive_sha256": ARCHIVE_SHA256[tag],
        "source_file_sha256": actual_source_hashes,
        "source_files_match_expected": actual_source_hashes == expected_source_hashes,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vulnerable-repo", type=Path, default=DEFAULT_VULNERABLE)
    parser.add_argument("--fixed-repo", type=Path, default=DEFAULT_FIXED)
    parser.add_argument("--build-python", default="/opt/homebrew/opt/python@3.11/bin/python3.11")
    parser.add_argument("--test-python", default="python3.13")
    parser.add_argument("--output-dir", type=Path, default=CASE_DIR / "results" / "full-evaluation")
    args = parser.parse_args()

    vulnerable = args.vulnerable_repo.resolve()
    fixed = args.fixed_repo.resolve()
    output_dir = args.output_dir.resolve()
    wheel_root = output_dir / "wheels"
    phases = {}
    base_env = os.environ.copy()
    base_env["PYTHONDONTWRITEBYTECODE"] = "1"
    base_env["PIP_NO_INDEX"] = "1"
    base_env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"

    for label, repo, tag in (
        ("vulnerable", vulnerable, "v4.5.3"),
        ("fixed", fixed, "v4.5.4"),
    ):
        wheel_dir = wheel_root / label
        wheel_dir.mkdir(parents=True, exist_ok=True)
        phases[f"{label}_build"] = run_phase(
            f"{label}_build",
            [
                args.build_python,
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                str(wheel_dir),
                str(repo),
            ],
            ROOT,
            base_env,
            output_dir,
        )
        test_env = dict(base_env)
        test_env["PYTHONPATH"] = str(repo)
        phases[f"{label}_ip_plugin_test"] = run_phase(
            f"{label}_ip_plugin_test",
            [args.test_python, "-m", "unittest", IP_TEST, "-v"],
            repo / "tests",
            test_env,
            output_dir,
        )

    fixture_env = dict(base_env)
    fixture_env["PYTHONPATH"] = str(ROOT / "src")
    phases["fixture_evaluation"] = run_phase(
        "fixture_evaluation",
        [
            sys.executable,
            str(CASE_DIR / "reproduce.py"),
            "--vulnerable-repo",
            str(vulnerable),
            "--fixed-repo",
            str(fixed),
        ],
        ROOT,
        fixture_env,
        output_dir,
    )

    wheel_artifacts = {}
    for label in ("vulnerable", "fixed"):
        wheels = sorted((wheel_root / label).glob("*.whl"))
        wheel_artifacts[label] = [
            {
                "path": str(wheel),
                "size_bytes": wheel.stat().st_size,
                "sha256": file_sha256(wheel),
            }
            for wheel in wheels
        ]
        if phases[f"{label}_build"]["exit_code"] == 0 and not wheels:
            phase = phases[f"{label}_build"]
            phase["exit_code"] = 1
            phase["status"] = "failed_or_blocked"
            with Path(phase["log"]).open("a", encoding="utf-8") as log:
                log.write("Build command succeeded but produced no wheel artifact.\n")

    report = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version,
        "revisions": {
            "vulnerable": revision_record(vulnerable, "v4.5.3"),
            "fixed": revision_record(fixed, "v4.5.4"),
        },
        "phase_scope": {
            "build": "local wheel build with --no-deps and --no-build-isolation",
            "upstream_test": f"{IP_TEST}; Glances test config sets public_disabled=True",
            "fixtures": "actual source methods with in-memory urllib/SafeFetcher responses and synthetic DNS",
            "network": "no external or internal network requests; no sockets opened by fixture evaluation",
        },
        "phases": phases,
        "wheel_artifacts": wheel_artifacts,
        "execution_time_seconds": round(sum(phase["elapsed_seconds"] for phase in phases.values()), 3),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "evaluation.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    sources_match = all(
        record["source_files_match_expected"]
        for record in report["revisions"].values()
    )
    return 0 if sources_match and all(phase["exit_code"] == 0 for phase in phases.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
