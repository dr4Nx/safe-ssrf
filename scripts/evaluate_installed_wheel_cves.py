#!/usr/bin/env python3
"""Run the prepared SSRF fixture matrix against an installed Safe Egress wheel.

The runner never installs dependencies. Every selected harness uses synthetic
DNS and/or in-memory HTTP. Supply already provisioned interpreters and a wheel
install target; phase logs and a JSON report are written to the output folder.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]


def _revision(path: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=path, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip()


def _tree_hash(path: Path) -> str | None:
    if not path.is_dir():
        return None
    ignored = {".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
    digest = hashlib.sha256()
    for item in sorted(p for p in path.rglob("*") if p.is_file() and not ignored.intersection(p.parts)):
        relative = item.relative_to(path).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        contents_hash = hashlib.sha256(item.read_bytes()).digest()
        digest.update(contents_hash)
    return digest.hexdigest()


def _runtime_metadata(python: str, wheel_site: Path) -> dict[str, object]:
    code = (
        "import importlib.metadata as m, json, platform, sys; "
        "names=('requests','httpx','aiohttp','urllib3','pydantic','yarl','pytest'); "
        "versions={name: next((d.version for d in m.distributions() if d.metadata.get('Name','').lower()==name), None) for name in names}; "
        "print(json.dumps({'python':sys.version,'platform':platform.platform(),'packages':versions}))"
    )
    result = subprocess.run(
        [python, "-c", code], cwd="/tmp",
        env={**os.environ, "PYTHONPATH": str(wheel_site)},
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    if result.returncode != 0:
        return {"exit_code": result.returncode, "output": result.stdout}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"exit_code": result.returncode, "output": result.stdout}


def _run_phase(
    name: str,
    command: list[str],
    cwd: Path,
    env: dict[str, str],
    output: Path,
) -> dict[str, object]:
    started = time.monotonic()
    try:
        result = subprocess.run(
            command, cwd=cwd, env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        )
        log, exit_code = result.stdout, result.returncode
    except OSError as exc:
        log, exit_code = f"{type(exc).__name__}: {exc}\n", 127
    elapsed = round(time.monotonic() - started, 3)
    log_path = output / f"{name}.log"
    log_path.write_text(log, encoding="utf-8")
    return {
        "command": command,
        "cwd": str(cwd),
        "pythonpath": env.get("PYTHONPATH", ""),
        "exit_code": exit_code,
        "status": "passed" if exit_code == 0 else "failed",
        "elapsed_seconds": elapsed,
        "log": str(log_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python311", type=Path, required=True)
    parser.add_argument("--python313", type=Path, required=True)
    parser.add_argument("--wheel-site", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "results" / "installed-wheel-cve-matrix")
    parser.add_argument("--ldr-repo", type=Path, default=ROOT.parent / "local-deep-research-vuln")
    parser.add_argument("--nanobot-repo", type=Path, default=ROOT.parent / "nanobot-benchmark-hardened")
    parser.add_argument("--langchain-community", type=Path, default=ROOT.parent / "ssrf-study" / "checkout" / "libs" / "community")
    parser.add_argument("--pyjwt-redirect-repo", type=Path, default=ROOT.parent / "pyjwt-2.13.0")
    parser.add_argument("--pyjwt-scheme-repo", type=Path, default=ROOT.parent / "pyjwt-2.12.1")
    parser.add_argument("--pyjwt-current-repo", type=Path, default=ROOT.parent / "pyjwt-source")
    parser.add_argument("--glances-vulnerable", type=Path, default=ROOT.parent / "glances-v4.5.3")
    parser.add_argument("--glances-fixed", type=Path, default=ROOT.parent / "glances-v4.5.4")
    parser.add_argument("--kolibri-benchmark", type=Path, default=ROOT.parent / "kolibri-ssrf-benchmark")
    parser.add_argument("--urllib3-version", default="2.3.0")
    args = parser.parse_args()

    wheel_site = args.wheel_site.resolve()
    output = args.output_dir.resolve()
    # Preserve virtualenv symlink paths: resolving them can discard pyvenv.cfg.
    py311 = str(args.python311.expanduser())
    py313 = str(args.python313.expanduser())

    # Fail before running the other 15 phases if the selected Python 3.13
    # environment cannot run the urllib3 reproduction. This avoids recording
    # an otherwise confusing partial matrix after a long run.
    urllib3_probe = subprocess.run(
        [py313, "-c", "import urllib3; print(urllib3.__version__)"],
        cwd="/tmp",
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    installed_urllib3 = urllib3_probe.stdout.strip()
    if urllib3_probe.returncode != 0:
        parser.error(
            "--python313 must have urllib3 installed; its probe failed: "
            + installed_urllib3
        )
    if installed_urllib3 != args.urllib3_version:
        parser.error(
            f"--python313 has urllib3 {installed_urllib3}, but "
            f"--urllib3-version requires {args.urllib3_version}"
        )
    output.mkdir(parents=True, exist_ok=True)

    phases: dict[str, dict[str, object]] = {}

    def phase(
        name: str,
        python: str,
        command: list[str],
        cwd: Path,
        extra_paths: list[Path] = (),
        extra_env: dict[str, str] | None = None,
    ) -> None:
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PIP_NO_INDEX"] = "1"
        environment["PYTHONPATH"] = os.pathsep.join(
            [str(wheel_site), *(str(path.resolve()) for path in extra_paths), *(p for p in (environment.get("PYTHONPATH", ""),) if p)]
        )
        environment.update(extra_env or {})
        phases[name] = _run_phase(name, [python, *command], cwd.resolve(), environment, output)

    ldr_harness = ROOT / "examples/cve-repros/local-deep-research/grader/source_path_harness.py"
    for case in ("security", "redirect", "parser_differential", "utility", "large_utility"):
        phase(
            f"requests_ldr_{case}", py311,
            [str(ldr_harness), "--repo", str(args.ldr_repo.resolve()), "--mode", "compat", "--case", case],
            ROOT,
        )

    phase(
        "requests_kolibri",
        py311,
        [
            str(ROOT / "scripts/run_kolibri_installed_wheel.py"),
            "--benchmark", str(args.kolibri_benchmark.resolve()),
            "--expected-site", str(wheel_site),
        ],
        ROOT,
        [args.kolibri_benchmark],
    )

    nanobot_harness = ROOT / "examples/cve-repros/nanobot/grader/source_path_harness.py"
    for case in ("security", "utility"):
        phase(
            f"httpx_nanobot_{case}", py311,
            [str(nanobot_harness), "--repo", str(args.nanobot_repo.resolve()), "--mode", "hardened", "--case", case],
            ROOT,
        )

    crawlee_vulnerable = ROOT.parent / "crawlee-python-v1.6.3"
    crawlee_fixed = ROOT.parent / "crawlee-python-v1.7.0"
    phase(
        "httpx_crawlee_sitemap_ssrf",
        py311,
        [
            "-m", "unittest", "discover", "-s",
            str(ROOT / "examples/cve-repros/crawlee"), "-p", "test_*.py", "-v",
        ],
        ROOT,
        extra_env={
            "CRAWLEE_VULNERABLE": str(crawlee_vulnerable.resolve()),
            "CRAWLEE_FIXED": str(crawlee_fixed.resolve()),
        },
    )

    phase(
        "aiohttp_langchain_community",
        py311,
        ["-m", "pytest", "-q", str(ROOT / "examples/langchain-ssrf/test_web_research_integration.py")],
        ROOT,
        [ROOT / "examples/langchain-ssrf", args.langchain_community],
    )

    pyjwt_harness = ROOT / "examples/pyjwt-ssrf/reproduce.py"
    phase(
        "urllib_pyjwt_redirect", py311,
        [str(pyjwt_harness), "--repo", str(args.pyjwt_redirect_repo.resolve()), "--mode", "hardened"], ROOT,
    )
    phase(
        "urllib_pyjwt_file_scheme", py311,
        [str(pyjwt_harness), "--repo", str(args.pyjwt_scheme_repo.resolve()), "--mode", "hardened-scheme"], ROOT,
    )
    phase(
        "urllib_pyjwt_current_redirect", py311,
        [str(pyjwt_harness), "--repo", str(args.pyjwt_current_repo.resolve()), "--mode", "fixed-current"], ROOT,
    )
    phase(
        "urllib_pyjwt_current_file_scheme", py311,
        [str(pyjwt_harness), "--repo", str(args.pyjwt_current_repo.resolve()), "--mode", "fixed-current-scheme"], ROOT,
    )

    glances_harness = ROOT / "examples/glances-ssrf/reproduce.py"
    phase(
        "urllib_glances", py311,
        [str(glances_harness), "--vulnerable-repo", str(args.glances_vulnerable.resolve()), "--fixed-repo", str(args.glances_fixed.resolve())],
        ROOT,
        [ROOT / "examples/glances-ssrf"],
    )

    urllib3_harness = ROOT / "examples/urllib3-cve-2025-50181/reproduce.py"
    phase(
        "urllib3_version_check", py313,
        ["-c", f"import sys, urllib3; print(urllib3.__version__); sys.exit(urllib3.__version__ != {args.urllib3_version!r})"],
        ROOT,
    )
    phase("urllib3_redirect", py313, [str(urllib3_harness)], ROOT)

    import_check = {}
    for label, python in (("python311", py311), ("python313", py313)):
        result = subprocess.run(
            [python, "-c", "import safe_egress; print(safe_egress.__file__)"],
            cwd="/tmp", env={**os.environ, "PYTHONPATH": str(wheel_site)}, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        )
        import_check[label] = {"exit_code": result.returncode, "module_path": result.stdout.strip()}

    wheel = args.wheel.resolve()
    wheel_hashes = {str(wheel): hashlib.sha256(wheel.read_bytes()).hexdigest()}
    repositories = {
        "local_deep_research": args.ldr_repo,
        "kolibri_benchmark": args.kolibri_benchmark,
        "nanobot_hardened": args.nanobot_repo,
        "crawlee_vulnerable": crawlee_vulnerable,
        "crawlee_fixed": crawlee_fixed,
        "langchain_community": args.langchain_community,
        "pyjwt_redirect": args.pyjwt_redirect_repo,
        "pyjwt_scheme": args.pyjwt_scheme_repo,
        "pyjwt_current": args.pyjwt_current_repo,
        "glances_vulnerable": args.glances_vulnerable,
        "glances_fixed": args.glances_fixed,
    }
    report = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "fixture_network": "synthetic DNS and in-memory responses; no external systems or sockets",
        "python_interpreters": {"python311": py311, "python313": py313},
        "runtime_metadata": {
            "python311": _runtime_metadata(py311, wheel_site),
            "python313": _runtime_metadata(py313, wheel_site),
        },
        "urllib3_required_version": args.urllib3_version,
        "wheel_site": str(wheel_site),
        "wheel_sha256": wheel_hashes,
        "installed_module_origin": import_check,
        "revisions": {
            name: {
                "path": str(path.resolve()),
                "git_commit": _revision(path.resolve()),
                "source_tree_sha256": _tree_hash(path.resolve()),
            }
            for name, path in repositories.items()
        },
        "phases": phases,
        "execution_time_seconds": round(sum(float(item["elapsed_seconds"]) for item in phases.values()), 3),
    }
    report_path = output / "evaluation.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if all(item["exit_code"] == 0 for item in phases.values()) and all(
        item["exit_code"] == 0 for item in import_check.values()
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
