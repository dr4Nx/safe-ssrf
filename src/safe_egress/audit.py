"""Best-effort AST inventory of common direct network request calls.

This is a sink inventory, not taint analysis and not proof of SSRF. Dynamic
imports, wrapper methods, and custom clients can be missed.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
from pathlib import Path
import sys
from collections.abc import Iterable


_REQUEST_METHODS = {
    "get", "post", "put", "patch", "delete", "head", "options", "request", "send", "stream", "urlopen", "open"
}


@dataclass(frozen=True, slots=True)
class AuditFinding:
    path: str
    line: int
    call: str
    policy_bound: bool = False


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    return None


def _imports(tree: ast.Module) -> tuple[dict[str, str], dict[str, str]]:
    modules: dict[str, str] = {}
    symbols: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                root = item.name.split(".", 1)[0]
                if root in {"requests", "httpx", "aiohttp", "urllib3", "urllib", "socket", "ftplib", "http", "safe_egress"}:
                    modules[item.asname or root] = item.name if item.asname else root
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".", 1)[0]
            if root in {"requests", "httpx", "aiohttp", "urllib3", "urllib", "socket", "ftplib", "http", "safe_egress"}:
                for item in node.names:
                    symbols[item.asname or item.name] = f"{node.module}.{item.name}"
    return modules, symbols


def _resolve_name(name: str | None, modules: dict[str, str], symbols: dict[str, str]) -> str | None:
    if not name:
        return None
    if name in symbols:
        return symbols[name]
    first, dot, rest = name.partition(".")
    if first in modules:
        return modules[first] + (dot + rest if dot else "")
    return name


def _client_variables(tree: ast.Module, modules: dict[str, str], symbols: dict[str, str]) -> dict[str, str]:
    """Track simple assignments like ``session = requests.Session()``."""
    variables: dict[str, str] = {}
    safe_constructors = {
        "safe_egress.SafeFetcher",
        "safe_egress.client.SafeFetcher",
        "safe_egress.requests_adapter.SafeRequestsSession",
        "safe_egress.httpx_adapter.SafeClient",
        "safe_egress.httpx_adapter.SafeAsyncClient",
        "safe_egress.aiohttp_adapter.safe_aiohttp_session",
        "safe_egress.urllib3_adapter.SafeUrllib3Client",
        "safe_egress.urllib_adapter.SafeUrllibOpener",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                value = item.context_expr
                if isinstance(value, ast.Call):
                    constructor = _resolve_name(_dotted_name(value.func), modules, symbols)
                    if constructor in safe_constructors:
                        for target in (item.optional_vars,):
                            if isinstance(target, ast.Name):
                                variables[target.id] = constructor
            continue
        else:
            continue
        if not isinstance(value, ast.Call):
            continue
        constructor = _resolve_name(_dotted_name(value.func), modules, symbols)
        if constructor in safe_constructors:
            kind = constructor
        elif constructor == "requests.Session":
            kind = "requests.Session"
        elif constructor in {"httpx.Client", "httpx.AsyncClient"}:
            kind = constructor
        elif constructor == "aiohttp.ClientSession":
            kind = constructor
        elif constructor in {
            "urllib3.PoolManager",
            "urllib3.ProxyManager",
            "urllib3.connectionpool.HTTPConnectionPool",
            "urllib3.connectionpool.HTTPSConnectionPool",
        }:
            kind = constructor
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                variables[target.id] = kind
    return variables


def scan_source(source: str, path: str = "<string>") -> list[AuditFinding]:
    """Return calls to common network clients found in Python source."""
    tree = ast.parse(source, filename=path)
    modules, symbols = _imports(tree)
    client_variables = _client_variables(tree, modules, symbols)
    findings: list[AuditFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _resolve_name(_dotted_name(node.func), modules, symbols)
        if not name:
            continue
        parts = name.split(".")
        root = parts[0]
        if root in client_variables and parts[-1] in _REQUEST_METHODS:
            client = client_variables[root]
            policy_bound = client.startswith("safe_egress.")
            findings.append(AuditFinding(path, node.lineno, f"{client}.{parts[-1]}", policy_bound))
        elif root in {"requests", "httpx"} and parts[-1] in _REQUEST_METHODS:
            findings.append(AuditFinding(path, node.lineno, name))
        elif root == "urllib3" and (
            name == "urllib3.request"
            or (
                parts[-1] in {"request", "urlopen"}
                and any(
                    part in {"PoolManager", "ProxyManager", "HTTPConnectionPool", "HTTPSConnectionPool"}
                    for part in parts
                )
            )
        ):
            findings.append(AuditFinding(path, node.lineno, name))
        elif root == "aiohttp" and len(parts) >= 3 and parts[-2] == "ClientSession" and parts[-1] in _REQUEST_METHODS:
            findings.append(AuditFinding(path, node.lineno, name))
        elif name in {"urllib.request.urlopen", "urllib.request.urlretrieve", "urllib.urlopen"}:
            findings.append(AuditFinding(path, node.lineno, name))
        elif name == "socket.create_connection":
            findings.append(AuditFinding(path, node.lineno, name))
        elif name in {"http.client.HTTPConnection.request", "http.client.HTTPSConnection.request"}:
            findings.append(AuditFinding(path, node.lineno, name))
        elif name in {"ftplib.FTP.connect", "ftplib.FTP_TLS.connect"}:
            findings.append(AuditFinding(path, node.lineno, name))
    return sorted(findings, key=lambda item: (item.path, item.line, item.call))


def scan_paths(paths: Iterable[Path]) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    for path in paths:
        files = [path] if path.is_file() else sorted(path.rglob("*.py"))
        for file in files:
            try:
                source = file.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            findings.extend(scan_source(source, str(file)))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inventory common direct Python network calls (heuristic).")
    parser.add_argument("paths", nargs="+", type=Path, help="Python files or directories to scan")
    args = parser.parse_args(argv)
    findings = scan_paths(args.paths)
    unprotected = 0
    for finding in findings:
        label = "policy-bound egress client" if finding.policy_bound else "possible outbound sink"
        print(f"{finding.path}:{finding.line}: {label}: {finding.call}")
        if not finding.policy_bound:
            unprotected += 1
    if not findings:
        print("No modeled outbound sinks found; this is not proof that the code makes no network requests.")
    elif not unprotected:
        print("All modeled client calls use a recognized Safe Egress client; this is not proof that no bypass exists.")
    return 1 if unprotected else 0


if __name__ == "__main__":
    sys.exit(main())
