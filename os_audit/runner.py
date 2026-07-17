"""Walk a directory and run the OS-level detectors over it.

Combines host-config hardening audit + native-code (C/C++) scanning into one
result. Fully offline and deterministic. Also exposed to repo_scan so a GitHub
repository is checked for OS-level bugs alongside IaC + secrets.

CLI:  python -m os_audit <path> [--json]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .host_config import audit_config_file
from .native_code import is_c_source, scan_c_source

_SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".next",
              "__pycache__", ".venv", "venv", "site-packages"}
_MAX_BYTES = 2_000_000
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class OsFinding:
    kind: str          # "host-config" | "native-code"
    rule_id: str
    severity: str
    title: str
    file: str
    line: int | None
    detail: str


@dataclass
class OsAuditResult:
    root: str
    findings: list[OsFinding] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"root": self.root, "summary": self.summary,
                "findings": [asdict(f) for f in self.findings]}


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file() or any(p in _SKIP_DIRS for p in path.parts):
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
        except OSError:
            continue
        yield path


def audit_tree(root: str | Path) -> OsAuditResult:
    root = Path(root)
    findings: list[OsFinding] = []

    for path in _iter_files(root):
        rel = str(path.relative_to(root))
        try:
            text = path.read_text(errors="replace")
        except Exception:
            continue

        for h in audit_config_file(path.name, rel, text):
            findings.append(OsFinding("host-config", h.rule_id, h.severity, h.title, h.file, h.line, h.detail))

        if is_c_source(path):
            for n in scan_c_source(text, rel):
                findings.append(OsFinding("native-code", n.rule_id, n.severity, n.title, n.file, n.line, n.detail))

    findings.sort(key=lambda f: (_SEV_RANK.get(f.severity, 9), f.file, f.line or 0))
    by_sev = Counter(f.severity for f in findings)
    result = OsAuditResult(root=str(root), findings=findings)
    result.summary = {
        "total": len(findings),
        "bySeverity": {s: by_sev.get(s, 0) for s in ("critical", "high", "medium", "low")},
        "byKind": dict(Counter(f.kind for f in findings)),
        "highestSeverity": min((f.severity for f in findings), key=lambda s: _SEV_RANK.get(s, 9), default="none"),
    }
    return result


def _main() -> int:
    ap = argparse.ArgumentParser(description="Audit a directory for OS-level and low-level native bugs.")
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    res = audit_tree(args.path)
    if args.json:
        print(json.dumps(res.to_dict(), indent=2))
        return 0
    print(f"OS audit: {res.root}")
    print(f"  {res.summary['total']} findings — {res.summary['bySeverity']}")
    for f in res.findings:
        print(f"  [{f.severity:8}] {f.kind:12} {f.rule_id:12} {f.file}:{f.line or '-'}  {f.title}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
