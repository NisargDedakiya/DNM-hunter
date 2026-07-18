"""Unified scanner CLI.

    nh-scan <path> [--format text|json|sarif] [--output FILE]
                   [--fail-on critical|high|medium|low|none]

Exit code is non-zero when a finding at or above --fail-on is present, so it can
gate CI. Default --fail-on is high.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .orchestrator import scan, scan_many
from .sarif import to_sarif

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 99}


def _render_text(result) -> str:
    s = result.summary
    lines = [f"Target: {result.target}",
             f"  {s.get('total', 0)} findings — {s.get('bySeverity', {})}",
             f"  by scanner: {s.get('byScanner', {})}"]
    for e in result.errors:
        lines.append(f"  ⚠ {e}")
    for f in result.findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        vrt = f"  [{f.vrt}]" if f.vrt else ""
        lines.append(f"  [{f.severity:8}] {f.scanner:15} {loc}  {f.title}{vrt}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(prog="nh-scan",
                                 description="NisargHunter AI unified security scanner (VRT-mapped, SARIF-capable).")
    ap.add_argument("path", nargs="+", help="one or more directories / repo checkouts to scan")
    ap.add_argument("--format", choices=["text", "json", "sarif", "md", "html"], default="text")
    ap.add_argument("--output", "-o", help="write to a file instead of stdout")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"],
                    default="high", help="exit non-zero if a finding at/above this severity exists")
    args = ap.parse_args()

    missing = [p for p in args.path if not Path(p).exists()]
    if missing:
        print(f"error: path(s) not found: {', '.join(missing)}", file=sys.stderr)
        return 2

    result = scan(args.path[0]) if len(args.path) == 1 else scan_many(args.path)

    if args.format == "json":
        out = json.dumps(result.to_dict(), indent=2)
    elif args.format == "sarif":
        out = json.dumps(to_sarif(result), indent=2)
    elif args.format in ("md", "html"):
        from report_gen import build_report, to_html, to_markdown
        rep = build_report(result)
        out = to_markdown(rep) if args.format == "md" else to_html(rep)
    else:
        out = _render_text(result)

    if args.output:
        Path(args.output).write_text(out)
        print(f"wrote {args.format} report to {args.output}", file=sys.stderr)
    else:
        print(out)

    # CI gate
    if args.fail_on != "none":
        threshold = _SEV_ORDER[args.fail_on]
        if any(_SEV_ORDER.get(f.severity, 99) <= threshold for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
