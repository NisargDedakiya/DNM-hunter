"""`python -m web_attack` — active injection scan of a live target, or an offline
demo.

    python -m web_attack https://staging.example.com/        # live (authorised)
    python -m web_attack --demo                              # offline vulnerable app

Live mode auto-scopes to the target's host — you are authorising the host you
name. It refuses to crawl or test anything outside that scope. Out-of-band SSRF
confirmation needs a real interaction server (see the README); without one, SSRF
is reported as inconclusive rather than guessed. The same applies to email header
injection — it is only *confirmed* by an out-of-band mail delivery, so without an
email-capable collaborator it stays a lead. Contact-form abuse (missing rate
limiting) is confirmed fully in-band and needs no collaborator.
"""

from __future__ import annotations

import argparse
import json
import sys
from urllib.parse import urlsplit

from verify import InMemoryInteractionServer, ScopeGuard
from verify.oracles import TimingOracle

from .engine import WebAttackEngine


def _run_demo() -> int:
    # Import the test's simulated app so the demo needs no network.
    from web_attack.tests.test_web_attack import SEED, VulnApp

    server = InMemoryInteractionServer()
    engine = WebAttackEngine(ScopeGuard({"app.test"}), client=VulnApp(server),
                             interaction_server=server, timing=TimingOracle(trials=1))
    _print(engine.run(SEED), demo=True)
    return 0


def _print(report, demo=False) -> None:
    print(f"Active injection scan — {report.seed}")
    print(f"  crawled {report.pages_crawled} page(s), {report.injection_points} injection point(s), "
          f"{report.candidates_tested} candidate(s) tested")
    if not report.findings:
        print("  no injection confirmed by an oracle.")
    for f in report.findings:
        print(f"\n  [{f.severity.upper():8}] {f.title}  ({f.vrt})")
        print(f"     {f.method} {f.url}  param='{f.param}'")
        print(f"     verified via {f.oracle} (confidence {f.confidence:.2f}): {f.evidence}")
    print(f"\n  verdicts: {json.dumps(report.summary.get('verdicts', {}))}")
    if demo:
        print("  (demo target — the same code path runs against a real authorised host.)")


def main() -> int:
    ap = argparse.ArgumentParser(description="Active web-injection engine (crawl → inject → verify).")
    ap.add_argument("url", nargs="?", help="seed URL of the authorised target")
    ap.add_argument("--demo", action="store_true", help="run against the built-in offline vulnerable app")
    ap.add_argument("--subdomains", action="store_true", help="also test subdomains of the target host")
    ap.add_argument("--max-pages", type=int, default=25)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if args.demo:
        return _run_demo()
    if not args.url:
        ap.error("provide a target URL, or use --demo")

    host = urlsplit(args.url).hostname or ""
    if not host:
        ap.error("could not parse a host from the URL")
    scope = ScopeGuard({host}, allow_subdomains=args.subdomains)
    # No interaction server on the CLI by default → SSRF stays inconclusive, not guessed.
    engine = WebAttackEngine(scope, client=None, max_pages=args.max_pages)
    report = engine.run(args.url)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
