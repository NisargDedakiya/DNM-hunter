"""OWASP coverage map — an honest, per-category mapping of the OWASP Top 10 for
web applications (2021) and the OWASP API Security Top 10 (2023) to the
DNM-Hunter scanner tiers.

Where the Bugcrowd VRT map (``vrt/coverage.py``) answers "which detector owns
each VRT row", this answers the question hunters actually ask first: "how well
do you cover the OWASP Top 10?". Each category records the *tier* that owns it —

    static   : decidable from source (code_audit / contract_audit / iac_scan /
               secret_scanner / binary_audit) — the rule ids are listed.
    partial  : a static lead exists, but confirmation needs a running target
               (e.g. IDOR/BOLA — SAST flags the shape, runtime proves the
               missing authorization check).
    dynamic  : only decidable against a live target (web_probe / gvm_scan).
    manual   : business-logic / process review; no scanner decides it.

This is deliberately conservative: we claim "static" only where a rule actually
fires, "partial" where we surface a lead, and "manual"/"dynamic" everywhere a
static source scanner genuinely cannot reach. Nothing here is aspirational.

CLI:  python -m vrt.owasp [--json] [--tier static|partial|dynamic|manual]
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass

STATIC, PARTIAL, DYNAMIC, MANUAL = "static", "partial", "dynamic", "manual"


@dataclass
class OwaspCategory:
    id: str                 # "A01" / "API3"
    title: str
    tier: str               # static | partial | dynamic | manual
    detectors: list[str]    # rule ids / scanner tiers that contribute
    note: str

    def to_dict(self) -> dict:
        return asdict(self)


# ── OWASP Top 10 for Web Applications (2021) ──
WEB_2021: list[OwaspCategory] = [
    OwaspCategory("A01", "Broken Access Control", PARTIAL,
                  ["CA-IDOR", "CA-MASSASSIGN", "contract_audit", "web_probe"],
                  "code_audit flags IDOR/mass-assignment shapes; the missing "
                  "authorization check is confirmed at runtime (forced browsing, "
                  "admin access, privilege escalation)."),
    OwaspCategory("A02", "Cryptographic Failures", STATIC,
                  ["CA-HASH", "CA-CIPHER", "CA-RSAKEY", "CA-SEED", "CA-IV",
                   "CA-HTTP", "CA-TLSVERIFY", "CA-JWT-SECRET", "CA-PLAINTEXTPW",
                   "secret_scanner"],
                  "Weak hashes/ciphers, cleartext transport, TLS-verify off, weak "
                  "randomness, plaintext passwords and hardcoded keys are all "
                  "code-visible."),
    OwaspCategory("A03", "Injection", STATIC,
                  ["CA-SQLI", "CA-NOSQL", "CA-CMDI", "CA-EVAL", "CA-LDAP",
                   "CA-XXE", "CA-SSTI", "CA-CRLF", "CA-XSS"],
                  "Taint-aware SQL/NoSQL/command/LDAP/template injection, XXE and "
                  "XSS sinks; parameterised queries are not flagged."),
    OwaspCategory("A04", "Insecure Design", MANUAL,
                  ["manual", "web_probe"],
                  "Business-logic flaws (unlimited coupons/resets, workflow "
                  "abuse) are a design property; rate-limiting gaps are probed "
                  "live. No static rule decides intent."),
    OwaspCategory("A05", "Security Misconfiguration", STATIC,
                  ["CA-DEBUG", "CA-CORS", "CA-COOKIE", "CA-DEFAULTCRED",
                   "CA-GRAPHQL", "CA-SWAGGER", "CA-CSRF", "iac_scan", "web_probe"],
                  "Debug on, permissive CORS, default creds, exposed docs, cookie "
                  "flags in code; live header/TLS checks via web_probe."),
    OwaspCategory("A06", "Vulnerable & Outdated Components", DYNAMIC,
                  ["gvm_scan", "recon", "iac_scan"],
                  "Version fingerprinting + CVE lookup needs a live target and a "
                  "vulnerability database; a full SCA (manifest→CVE) is a "
                  "dependency-scanner concern, not source SAST."),
    OwaspCategory("A07", "Identification & Authentication Failures", PARTIAL,
                  ["CA-JWT-NONE", "CA-JWT-NOVERIFY", "CA-JWT-SECRET",
                   "CA-PLAINTEXTPW", "web_probe"],
                  "JWT none/verify-off/weak-secret and plaintext passwords are "
                  "static; session fixation, brute force and 2FA bypass are "
                  "runtime behaviours."),
    OwaspCategory("A08", "Software & Data Integrity Failures", PARTIAL,
                  ["CA-DESERIAL", "iac_scan"],
                  "Insecure deserialization is static; unsigned updates, CI/CD "
                  "trust and dependency confusion are checked in IaC/pipeline "
                  "config and otherwise reviewed."),
    OwaspCategory("A09", "Security Logging & Monitoring Failures", MANUAL,
                  ["iac_scan", "manual"],
                  "iac_scan flags disabled cloud logging; whether the app logs "
                  "auth events / alerts is a config & process review."),
    OwaspCategory("A10", "Server-Side Request Forgery (SSRF)", STATIC,
                  ["CA-SSRF", "CA-REDIR", "web_probe"],
                  "Outbound requests to untrusted URLs are flagged from source; "
                  "metadata/internal-IP reachability is confirmed live."),
]

# ── OWASP API Security Top 10 (2023) ──
API_2023: list[OwaspCategory] = [
    OwaspCategory("API1", "Broken Object Level Authorization (BOLA)", PARTIAL,
                  ["CA-IDOR", "web_probe"],
                  "code_audit flags the user-id→object-lookup shape; swapping "
                  "object ids to prove missing authorization is a runtime step."),
    OwaspCategory("API2", "Broken Authentication", PARTIAL,
                  ["CA-JWT-NONE", "CA-JWT-NOVERIFY", "CA-JWT-SECRET", "web_probe"],
                  "Weak/none JWT and hardcoded secrets are static; expired-token "
                  "acceptance, missing MFA and session reuse are runtime."),
    OwaspCategory("API3", "Broken Object Property Level Authorization (BOPLA)", STATIC,
                  ["CA-MASSASSIGN"],
                  "Mass assignment (whole request object bound to a model) lets a "
                  "client set fields like isAdmin — detectable from source."),
    OwaspCategory("API4", "Unrestricted Resource Consumption", DYNAMIC,
                  ["web_probe", "manual"],
                  "Missing pagination/upload/rate limits are load-based; measured "
                  "against a live endpoint, not source."),
    OwaspCategory("API5", "Broken Function Level Authorization (BFLA)", PARTIAL,
                  ["CA-IDOR", "web_probe"],
                  "A non-admin reaching an admin function is confirmed by calling "
                  "restricted routes live; source only hints at the surface."),
    OwaspCategory("API6", "Unrestricted Access to Sensitive Business Flows", MANUAL,
                  ["manual"],
                  "OTP/coupon/reset/reward abuse is business-flow logic; requires "
                  "human modelling of the workflow."),
    OwaspCategory("API7", "Server-Side Request Forgery (SSRF)", STATIC,
                  ["CA-SSRF", "web_probe"],
                  "Same engine as A10, applied to API request handlers."),
    OwaspCategory("API8", "Security Misconfiguration", STATIC,
                  ["CA-CORS", "CA-GRAPHQL", "CA-SWAGGER", "CA-DEFAULTCRED",
                   "CA-DEBUG", "web_probe"],
                  "Exposed Swagger/GraphQL introspection, default creds, CORS and "
                  "debug endpoints from source; headers probed live."),
    OwaspCategory("API9", "Improper Inventory Management", DYNAMIC,
                  ["recon", "web_probe", "manual"],
                  "Forgotten/undocumented/old-version endpoints are found by "
                  "active endpoint discovery, not by reading one repo."),
    OwaspCategory("API10", "Unsafe Consumption of APIs", MANUAL,
                  ["manual"],
                  "Blind trust in third-party responses / missing signature "
                  "verification is an integration-design review."),
]

ALL: list[OwaspCategory] = WEB_2021 + API_2023


def report() -> dict:
    by_tier: dict[str, int] = {STATIC: 0, PARTIAL: 0, DYNAMIC: 0, MANUAL: 0}
    for c in ALL:
        by_tier[c.tier] = by_tier.get(c.tier, 0) + 1
    return {
        "total": len(ALL),
        "web_2021": len(WEB_2021),
        "api_2023": len(API_2023),
        "byTier": by_tier,
        # categories with any static/partial coverage
        "withStaticCoverage": sum(1 for c in ALL if c.tier in (STATIC, PARTIAL)),
    }


def _main() -> int:
    ap = argparse.ArgumentParser(description="OWASP Top 10 (Web 2021 + API 2023) coverage map.")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--tier", choices=[STATIC, PARTIAL, DYNAMIC, MANUAL],
                    help="list only categories in this coverage tier")
    args = ap.parse_args()

    cats = [c for c in ALL if not args.tier or c.tier == args.tier]
    if args.json:
        print(json.dumps({"report": report(), "categories": [c.to_dict() for c in cats]}, indent=2))
        return 0

    rep = report()
    print("OWASP coverage — Web Top 10 (2021) + API Security Top 10 (2023)\n")
    section = None
    for c in cats:
        sec = "Web Top 10 (2021)" if c in WEB_2021 else "API Security Top 10 (2023)"
        if sec != section:
            print(f"\n── {sec} ──")
            section = sec
        print(f"  {c.id:5} [{c.tier:7}] {c.title}")
        print(f"        detectors: {', '.join(c.detectors)}")
    print(f"\nTier totals: {json.dumps(rep['byTier'])}")
    print(f"{rep['withStaticCoverage']}/{rep['total']} categories have static or partial (source-visible) coverage.")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
