"""Scan a GitHub repository for vulnerabilities.

Composes the platform's existing static analysers over a repo checkout:
  1. clone (shallow) the repo — iac_scan.git_source.clone_repo
  2. IaC/DevOps misconfiguration — iac_scan.runner.IacScanRunner
  3. value-pattern secret detection — repo_scan.secret_scanner

Findings are normalised into one shape with a severity, and a summary is
produced. Everything is offline after the clone; scan_tree() runs against an
already-present directory so it is fully testable without network access.

CLI:  python -m repo_scan <github-url-or-owner/name> [--json]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    kind: str            # misconfig | host-config | native-code | llm-owasp | sast | smart-contract | secret
    rule_id: str
    title: str
    severity: str
    file: str
    line: int | None
    detail: str
    category: str = ""
    # Static-evidence confidence: "firm" (likely exploitable — input reaches a
    # sink / definitive misconfig), "tentative" (context-dependent, verify), or
    # "heuristic" (a lead needing manual review, e.g. IDOR authorization).
    confidence: str = "firm"


@dataclass
class RepoScanResult:
    repo: str
    findings: list[Finding] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "repo": self.repo,
            "error": self.error,
            "summary": self.summary,
            "findings": [asdict(f) for f in self.findings],
        }


def _summarize(findings: list[Finding]) -> dict:
    by_sev = Counter(f.severity for f in findings)
    by_kind = Counter(f.kind for f in findings)
    return {
        "total": len(findings),
        "bySeverity": {s: by_sev.get(s, 0) for s in ("critical", "high", "medium", "low", "info")},
        "byKind": dict(by_kind),
        "highestSeverity": min((f.severity for f in findings), key=lambda s: _SEV_ORDER.get(s, 99), default="none"),
    }


def scan_tree(path: str | Path, repo_label: str = "") -> RepoScanResult:
    """Run every static detector over an already-checked-out directory."""
    path = Path(path)
    result = RepoScanResult(repo=repo_label or str(path))
    findings: list[Finding] = []

    # 1) IaC / DevOps misconfiguration
    try:
        from iac_scan.runner import IacScanRunner
        for f in IacScanRunner(target_dir=str(path), project_id="repo-scan").run():
            findings.append(Finding(
                kind="misconfig",
                rule_id=f.get("rule_id", ""),
                title=f.get("title", ""),
                severity=f.get("severity", "medium"),
                file=f.get("file_path", ""),
                line=f.get("line"),
                detail=f.get("message", ""),
                category=f.get("category", ""),
            ))
    except Exception as exc:
        result.error = f"iac_scan failed: {type(exc).__name__}: {exc}"

    # 2) OS host-hardening config + low-level native-code (C/C++) bugs
    try:
        from os_audit import audit_tree as os_audit_tree
        for o in os_audit_tree(path).findings:
            findings.append(Finding(
                kind=o.kind,               # "host-config" | "native-code"
                rule_id=o.rule_id,
                title=o.title,
                severity=o.severity,
                file=o.file,
                line=o.line,
                detail=o.detail,
                category="os",
            ))
    except Exception as exc:
        prev = f"{result.error}; " if result.error else ""
        result.error = f"{prev}os_audit failed: {type(exc).__name__}: {exc}"

    # 3) OWASP LLM Top 10 — AI-application anti-patterns
    try:
        from llm_audit import scan_tree as llm_scan_tree
        for lf in llm_scan_tree(path):
            findings.append(Finding(
                kind="llm-owasp",
                rule_id=f"{lf.llm_id}:{lf.rule_id}",
                title=f"{lf.llm_id} {lf.category_name}: {lf.title}",
                severity=lf.severity,
                file=lf.file,
                line=lf.line,
                detail=lf.detail,
                category="llm",
            ))
    except Exception as exc:
        prev = f"{result.error}; " if result.error else ""
        result.error = f"{prev}llm_audit failed: {type(exc).__name__}: {exc}"

    # 4) Web-application source SAST (server-side injection, crypto, XSS/SSRF…)
    try:
        from code_audit import scan_tree as code_scan_tree
        for c in code_scan_tree(path):
            findings.append(Finding(
                kind="sast",
                rule_id=c.rule_id,
                title=c.title,
                severity=c.severity,
                file=c.file,
                line=c.line,
                detail=f"{c.detail} [VRT {c.vrt}{'; ' + c.cwe if c.cwe else ''}]",
                category="webapp",
                confidence=c.confidence,
            ))
    except Exception as exc:
        prev = f"{result.error}; " if result.error else ""
        result.error = f"{prev}code_audit failed: {type(exc).__name__}: {exc}"

    # 5) Solidity smart-contract static analysis
    try:
        from contract_audit import scan_tree as contract_scan_tree
        for sc in contract_scan_tree(path):
            findings.append(Finding(
                kind="smart-contract",
                rule_id=sc.rule_id,
                title=sc.title,
                severity=sc.severity,
                file=sc.file,
                line=sc.line,
                detail=f"{sc.detail} [VRT {sc.vrt}{'; ' + sc.swc if sc.swc else ''}]",
                category="web3",
            ))
    except Exception as exc:
        prev = f"{result.error}; " if result.error else ""
        result.error = f"{prev}contract_audit failed: {type(exc).__name__}: {exc}"

    # 5b) Mobile source SAST (Android + iOS — OWASP Mobile Top 10)
    try:
        from mobile_audit import scan_tree as mobile_scan_tree
        for mf in mobile_scan_tree(path):
            findings.append(Finding(
                kind="mobile-source",
                rule_id=mf.rule_id,
                title=mf.title,
                severity=mf.severity,
                file=mf.file,
                line=mf.line,
                detail=f"{mf.detail} [OWASP-Mobile {mf.owasp}; {mf.platform}"
                       f"{'; ' + mf.cwe if mf.cwe else ''}]",
                category=mf.platform,
                confidence=mf.confidence,
            ))
    except Exception as exc:
        prev = f"{result.error}; " if result.error else ""
        result.error = f"{prev}mobile_audit failed: {type(exc).__name__}: {exc}"

    # 6) Value-pattern secret detection
    try:
        from .secret_scanner import scan_secrets
        for s in scan_secrets(path):
            findings.append(Finding(
                kind="secret",
                rule_id=f"SECRET-{s.name.upper().replace(' ', '-')}",
                title=f"Hardcoded {s.name}",
                severity=s.severity,
                file=s.file,
                line=s.line,
                detail=f"{s.name} detected ({s.confidence} confidence): {s.redacted}"
                       + (f" — {s.note}" if s.note else ""),
                category=s.category,
                confidence="tentative" if s.note else "firm",
            ))
    except Exception as exc:
        prev = f"{result.error}; " if result.error else ""
        result.error = f"{prev}secret_scan failed: {type(exc).__name__}: {exc}"

    findings.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 99), f.file))
    result.findings = findings
    result.summary = _summarize(findings)
    return result


def scan_repo(repo: str, token: str | None = None, workdir: str | None = None) -> RepoScanResult:
    """Clone `repo` (a GitHub URL or owner/name) and scan it. If `repo` points at
    an existing local directory, scan it directly (no clone)."""
    token = token or os.environ.get("GITHUB_TOKEN", "")

    if Path(repo).is_dir():
        return scan_tree(repo, repo_label=repo)

    tmp_created = False
    if workdir is None:
        workdir = tempfile.mkdtemp(prefix="repo-scan-")
        tmp_created = True
    try:
        from iac_scan.git_source import clone_repo
        checkout = clone_repo(repo, token, Path(workdir))
        if not checkout:
            return RepoScanResult(repo=repo, error="clone failed (repo not found, private without token, or network blocked)")
        return scan_tree(checkout, repo_label=repo)
    finally:
        if tmp_created:
            import shutil
            shutil.rmtree(workdir, ignore_errors=True)


def _main() -> int:
    ap = argparse.ArgumentParser(description="Scan a GitHub repository for vulnerabilities.")
    ap.add_argument("repo", help="GitHub URL, owner/name, or a local path")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--token", default=None, help="GitHub token for private repos")
    args = ap.parse_args()

    res = scan_repo(args.repo, token=args.token)
    if args.json:
        print(json.dumps(res.to_dict(), indent=2))
        return 0 if not res.error else 1

    print(f"Repo: {res.repo}")
    if res.error:
        print(f"  ⚠ {res.error}")
    s = res.summary
    print(f"  {s.get('total', 0)} findings — {s.get('bySeverity', {})}")
    for f in res.findings:
        print(f"  [{f.severity:8}] {f.kind:9} {f.file}:{f.line or '-'}  {f.title}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
