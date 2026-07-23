"""`python -m verify` — a self-contained demo of the verification layer.

Runs each oracle against a built-in simulated target (no network, no live host)
so you can see exactly what a CONFIRMED / REFUTED / SKIPPED verdict looks like
and how the evidence reads. This is a demonstration harness, not a scanner — real
verification runs the same oracles against an authorised live target.
"""

from __future__ import annotations

import re
import urllib.parse

from .engine import VerificationEngine
from .http import HttpResponse
from .oracles import InMemoryInteractionServer
from .scope import ScopeGuard
from .types import Candidate, Identity, VulnClass

_HOST = "staging.example.test"
_URL = f"https://{_HOST}/item"


def _raw(req) -> str:
    return urllib.parse.unquote_plus((req.url or "") + " " + (req.body or ""))


class DemoTarget:
    """A deliberately vulnerable simulated app: time-based SQLi on ?id, raw
    reflection on ?q, SSRF on ?url, and a broken IDOR on ?doc."""

    def __init__(self, server: InMemoryInteractionServer):
        self.server = server

    def send(self, req) -> HttpResponse:
        s = _raw(req)
        m = re.search(r"(?:SLEEP|pg_sleep)\((\d+)", s, re.I)
        if m:
            return HttpResponse(200, {}, "ok", 40.0 + int(m.group(1)) * 1000.0)
        mk = re.search(r"<(dnmh[0-9a-f]+)>", s)
        if mk:
            return HttpResponse(200, {}, f"<h1>Results for <{mk.group(1)}></h1>")
        oa = re.search(r"([0-9a-f]+\.oast\.local)", s)
        if oa:
            self.server.trigger(oa.group(1), "http", "10.0.0.5")
            return HttpResponse(200, {}, "fetched")
        return HttpResponse(200, {}, "SSN=123-45-6789 owner=alice")  # IDOR: no authz check


def main() -> int:
    server = InMemoryInteractionServer()
    engine = VerificationEngine(ScopeGuard({_HOST}), client=DemoTarget(server),
                                interaction_server=server)
    candidates = [
        Candidate(VulnClass.BLIND_SQLI, _URL, param="id", base_value="1", source_rule="CA-SQLI"),
        Candidate(VulnClass.REFLECTED_XSS, _URL, param="q", source_rule="CA-XSS"),
        Candidate(VulnClass.SSRF, _URL, param="url", source_rule="CA-SSRF"),
        Candidate(VulnClass.IDOR, _URL, param="doc", base_value="42", owner_marker="SSN=123-45-6789",
                  identities=[Identity("owner", {"X-User": "owner"}, authorized=True),
                              Identity("attacker", {"X-User": "attacker"}, authorized=False)],
                  source_rule="CA-IDOR"),
        # out-of-scope target — must be refused
        Candidate(VulnClass.SSRF, "https://not-authorised.example.org/x", param="url"),
    ]
    print("Verification layer demo — oracle-backed, deterministic verdicts\n")
    for c in engine.verify_all(candidates):
        vclass = getattr(c.vuln_class, "value", c.vuln_class)
        verdict = getattr(c.verdict, "value", c.verdict)
        line = f"  [{verdict.upper():12}] {vclass:14} via {c.oracle:12} conf={c.confidence:.2f}"
        print(line)
        if c.evidence:
            print(f"        evidence: {c.evidence[0].detail}")
        else:
            print(f"        {c.note}")
    print("\nThe AI proposes candidates; these verdicts come only from observed evidence.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
