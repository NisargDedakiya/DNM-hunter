"""Unified scanner orchestrator — one entry point over the whole static suite.

Runs every applicable static analyser over a target directory and returns one
normalised, VRT-tagged, severity-ranked finding list plus a summary. This is the
production surface the platform (and CI) calls; individual modules remain usable
standalone.

Composition (each analyser is optional — a missing/broken one degrades the run
with an error note rather than failing the whole scan):

  repo_scan.scan_tree   → IaC/DevOps, OS/firmware, native code, LLM Top 10,
                          web-app SAST, smart contracts, secrets
  binary_audit          → ELF hardening + dangerous imports over any binaries

Output can be rendered as text, JSON, or SARIF 2.1.0 (see sarif.py).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class SuiteFinding:
    scanner: str          # which analyser produced it (code_audit, iac_scan, …)
    kind: str             # finding kind within that analyser
    rule_id: str
    title: str
    severity: str
    file: str
    line: int | None
    detail: str
    category: str = ""
    vrt: str = ""         # canonical Bugcrowd VRT id when known
    # Static-evidence confidence in exploitability: firm | tentative | heuristic.
    confidence: str = "firm"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SuiteResult:
    target: str
    findings: list[SuiteFinding] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "summary": self.summary,
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.findings],
        }


# repo_scan encodes the VRT id inside detail as "[VRT xxx; CWE-nn]" for the SAST
# and contract scanners. Pull it back out so the suite finding carries it first-class.
def _extract_vrt(detail: str) -> str:
    import re
    m = re.search(r"\[VRT\s+([a-z0-9_.]+)", detail)
    return m.group(1) if m else ""


def scan(target: str | Path) -> SuiteResult:
    target = Path(target)
    result = SuiteResult(target=str(target))
    findings: list[SuiteFinding] = []

    # ── static source/config/secret suite (via repo_scan's composition) ──
    try:
        from repo_scan.repo_scanner import scan_tree as repo_scan_tree
        rs = repo_scan_tree(target, repo_label=str(target))
        if rs.error:
            result.errors.append(rs.error)
        for f in rs.findings:
            findings.append(SuiteFinding(
                scanner=_scanner_for_kind(f.kind),
                kind=f.kind,
                rule_id=f.rule_id,
                title=f.title,
                severity=f.severity,
                file=f.file,
                line=f.line,
                detail=f.detail,
                category=f.category,
                vrt=_extract_vrt(f.detail),
                confidence=getattr(f, "confidence", "firm"),
            ))
    except Exception as exc:
        result.errors.append(f"repo_scan failed: {type(exc).__name__}: {exc}")

    # ── ELF binary hardening (not covered by the source suite) ──
    try:
        from binary_audit.elf import analyze_path
        for analysis in analyze_path(target):
            if not analysis.is_elf:
                continue
            for bf in analysis.findings:
                findings.append(SuiteFinding(
                    scanner="binary_audit",
                    kind="binary-hardening",
                    rule_id=bf.rule_id,
                    title=bf.title,
                    severity=bf.severity,
                    file=analysis.path,
                    line=None,
                    detail=bf.detail,
                    category="binary",
                    vrt="lack_of_binary_hardening.lack_of_exploit_mitigations",
                ))
    except Exception as exc:
        result.errors.append(f"binary_audit failed: {type(exc).__name__}: {exc}")

    findings.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 99), f.scanner, f.file))
    result.findings = findings
    result.summary = _summarize(findings)
    return result


def scan_many(targets: list[str | Path]) -> SuiteResult:
    """Scan several paths and merge into one result (used to scope a CI scan to
    first-party source without descending the whole monorepo)."""
    merged = SuiteResult(target=", ".join(str(t) for t in targets))
    for t in targets:
        r = scan(t)
        merged.findings.extend(r.findings)
        merged.errors.extend(r.errors)
    merged.findings.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 99), f.scanner, f.file))
    merged.summary = _summarize(merged.findings)
    return merged


_KIND_SCANNER = {
    "misconfig": "iac_scan",
    "host-config": "os_audit",
    "native-code": "os_audit",
    "llm-owasp": "llm_audit",
    "sast": "code_audit",
    "smart-contract": "contract_audit",
    "secret": "secret_scanner",
}


def _scanner_for_kind(kind: str) -> str:
    return _KIND_SCANNER.get(kind, kind)


def _summarize(findings: list[SuiteFinding]) -> dict:
    by_sev = Counter(f.severity for f in findings)
    by_scanner = Counter(f.scanner for f in findings)
    return {
        "total": len(findings),
        "bySeverity": {s: by_sev.get(s, 0) for s in ("critical", "high", "medium", "low", "info")},
        "byScanner": dict(by_scanner),
        "highestSeverity": min((f.severity for f in findings),
                               key=lambda s: _SEV_ORDER.get(s, 99), default="none"),
    }
