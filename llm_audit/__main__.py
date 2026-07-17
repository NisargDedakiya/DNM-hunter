"""CLI for the OWASP LLM Top 10 scanner.

Usage:  python -m llm_audit <path> [--json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import scan_llm_code, scan_tree


def main() -> int:
    ap = argparse.ArgumentParser(description="OWASP LLM Top 10 (2025) static scanner.")
    ap.add_argument("path", help="source tree or single file")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args()

    p = Path(args.path)
    findings = scan_tree(p) if p.is_dir() else scan_llm_code(p.read_text(errors="replace"), str(p))

    if args.json:
        print(json.dumps([f.__dict__ for f in findings], indent=2))
        return 0
    for f in sorted(findings, key=lambda x: x.severity):
        print(f"  [{f.severity:8}] {f.llm_id} {f.rule_id:8} {f.file}:{f.line}  {f.title}")
    print(f"\n{len(findings)} findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
