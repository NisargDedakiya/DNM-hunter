"""Unified scanner CLI.

    nh-scan <path> [--format text|json|sarif] [--output FILE]
                   [--fail-on critical|high|medium|low|none]

Exit code is non-zero when a finding at or above --fail-on is present, so it can
gate CI. Default --fail-on is high.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from .orchestrator import scan, scan_many
from .sarif import to_sarif

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 99}

# owner/repo (GitHub shorthand): two path segments of repo-safe chars, nothing more.
_SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _is_remote_repo(target: str) -> bool:
    """True when `target` names a GitHub repo to clone rather than a local path.

    A remote repo is a git URL (http/https/ssh/git@ or a .git suffix) or a bare
    `owner/repo` shorthand — but only when no such path exists on disk (a local
    directory always wins, so `./owner/repo` checkouts still scan in place)."""
    if Path(target).exists():
        return False
    t = target.strip()
    if t.startswith(("http://", "https://", "git@", "ssh://")) or t.endswith(".git"):
        return True
    return bool(_SLUG_RE.match(t))


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
    ap.add_argument("--token", default=None,
                    help="GitHub token for cloning a private repo (or set GITHUB_TOKEN)")
    args = ap.parse_args()

    # A single GitHub URL / owner-repo shorthand is cloned, then scanned like any
    # local checkout — this is what powers the webapp's "scan a GitHub repo" flow.
    if len(args.path) == 1 and _is_remote_repo(args.path[0]):
        return _scan_remote(args.path[0], args)

    missing = [p for p in args.path if not Path(p).exists()]
    if missing:
        print(f"error: path(s) not found: {', '.join(missing)}", file=sys.stderr)
        return 2

    result = scan(args.path[0]) if len(args.path) == 1 else scan_many(args.path)
    return _emit(result, args)


def _scan_remote(target: str, args) -> int:
    """Shallow-clone a GitHub repo into a temp dir, scan the checkout, clean up.

    Reuses the same orchestrator + renderers as a local scan, so every output
    format (text/json/sarif/md/html) works identically for a URL."""
    import shutil
    import tempfile

    from iac_scan.git_source import clone_repo

    token = args.token or os.environ.get("GITHUB_TOKEN", "")
    workdir = tempfile.mkdtemp(prefix="nh-scan-")
    try:
        checkout = clone_repo(target, token, Path(workdir))
        if checkout is None:
            print("error: clone failed (repo not found, private without --token, "
                  "or network blocked)", file=sys.stderr)
            return 2
        result = scan(checkout)
        result.target = target  # report the repo, not the temp path
        return _emit(result, args)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _emit(result, args) -> int:
    """Render `result` in the requested format, write it out, and apply the CI gate."""
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
