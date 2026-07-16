"""Honest VRT coverage map: for each of the ~400 Bugcrowd VRT rows, how this
platform can detect it, and with which module.

Methods:
  static       — a shipped static analyser finds it from source/config/binary
  dynamic      — a shipped runtime scanner / the agent finds it against a live target
  manual       — needs a human, economic-logic review, or physical access
  out_of_scope — hardware / automotive / RF / algorithmic bias: not automatable here

Rules are matched most-specific first (category + name substrings), then a
per-category default, then a global default of "manual". Detector names refer to
real modules in this repo, so the "static" tally reflects code that exists.
"""

from __future__ import annotations

from dataclasses import dataclass

from .taxonomy import VrtEntry, load, severity_rank

STATIC, DYNAMIC, MANUAL, OUT = "static", "dynamic", "manual", "out_of_scope"


@dataclass(frozen=True)
class Coverage:
    method: str
    detector: str
    note: str = ""


# (category_substr, name_substr, method, detector, note) — first match wins.
_SPECIFIC: list[tuple] = [
    # ── AI Application Security (mixed) ──
    ("ai application", "remote code execution", STATIC, "llm_audit+code_audit", "LLM05 improper output → sink"),
    ("ai application", "prompt injection", STATIC, "llm_audit", "LLM01"),
    ("ai application", "improper output", STATIC, "llm_audit+code_audit", "LLM05 / XSS sink"),
    ("ai application", "improper input", STATIC, "llm_audit", "LLM01 input handling"),
    ("ai application", "sensitive information disclosure", STATIC, "llm_audit+secret_scanner", "LLM06 / key leak"),
    ("ai application", "training data poisoning", STATIC, "llm_audit", "LLM04"),
    ("ai application", "vector and embedding", STATIC, "llm_audit", "LLM07"),
    ("ai application", "insufficient rate limiting", DYNAMIC, "runtime", "observe API throttling"),
    ("ai application", "denial-of-service", DYNAMIC, "runtime", "load/DoS observed live"),
    ("ai application", "model extraction", DYNAMIC, "ai_attack_surface_scan", "query-based extraction is live"),
    ("ai application", "adversarial example", MANUAL, "-", "requires model probing"),
    ("ai application", "ai safety", MANUAL, "-", "misinformation is a runtime/quality property"),
    # ── Server-Side Injection (mostly static) ──
    ("server-side injection", "sql injection", STATIC, "code_audit", "CA-SQLI"),
    ("server-side injection", "remote code execution", STATIC, "code_audit", "CA-CMDI/CA-EVAL"),
    ("server-side injection", "file inclusion", STATIC, "code_audit", "CA-LFI"),
    ("server-side injection", "xml external entity", STATIC, "code_audit", "CA-XXE"),
    ("server-side injection", "template injection", STATIC, "code_audit", "CA-SSTI"),
    ("server-side injection", "ldap injection", STATIC, "code_audit", "CA-LDAP"),
    ("server-side injection", "http response manipulation", STATIC, "code_audit", "CA-CRLF"),
    ("server-side injection", "content spoofing", DYNAMIC, "runtime", "reflected content is live"),
    ("server-side injection", "exposed data", DYNAMIC, "runtime", ""),
    # ── Smart Contract / DApp (static via contract_audit) ──
    ("smart contract", "", STATIC, "contract_audit", "Solidity SAST"),
    ("decentralized application", "insecure data storage", STATIC, "code_audit+secret_scanner", "plaintext key"),
    ("decentralized application", "improper authorization", STATIC, "contract_audit", "signature/authz checks"),
    ("decentralized application", "", MANUAL, "-", "DeFi/marketplace economic logic"),
    ("blockchain infrastructure", "", MANUAL, "-", "bridge validation logic"),
    ("protocol specific", "", MANUAL, "-", "staking/finalization economic logic"),
    ("zero knowledge", "", MANUAL, "-", "circuit/proof review"),
    # ── Cloud / IaC (static via iac_scan) ──
    ("cloud security", "identity and access management", STATIC, "iac_scan", "IAM misconfig rules"),
    ("cloud security", "storage misconfigurations", STATIC, "iac_scan", "bucket/at-rest rules"),
    ("cloud security", "network configuration", STATIC, "iac_scan", "open ports/segmentation"),
    ("cloud security", "misconfigured services", DYNAMIC, "cloud_recon", "exposed admin/debug live"),
    ("cloud security", "logging and monitoring", STATIC, "iac_scan", "logging disabled in IaC"),
    # ── Cryptographic Weakness (static where code-visible) ──
    ("cryptographic weakness", "weak hash", STATIC, "code_audit", "CA-HASH"),
    ("cryptographic weakness", "broken cryptography", STATIC, "code_audit", "CA-CIPHER"),
    ("cryptographic weakness", "insecure key generation", STATIC, "code_audit", "CA-RSAKEY"),
    ("cryptographic weakness", "insufficient entropy", STATIC, "code_audit", "CA-RANDOM"),
    ("cryptographic weakness", "key reuse", STATIC, "code_audit", "hardcoded key material"),
    ("cryptographic weakness", "side-channel", MANUAL, "-", "timing/power needs instrumentation"),
    ("cryptographic weakness", "insecure implementation", MANUAL, "-", "spec-conformance review"),
    ("cryptographic weakness", "insufficient verification", MANUAL, "-", ""),
    # ── OS / Firmware (static via os_audit) ──
    ("insecure os/firmware", "command injection", STATIC, "os_audit+code_audit", ""),
    ("insecure os/firmware", "hardcoded password", STATIC, "os_audit+secret_scanner", ""),
    ("insecure os/firmware", "", STATIC, "os_audit", "host-hardening/firmware config"),
    # ── Binary hardening / mobile ──
    ("lack of binary hardening", "", STATIC, "binary_audit+mobile_scan", "checksec/ELF"),
    ("mobile security", "", STATIC, "mobile_scan", "APK/plist misconfig"),
    ("insecure data storage", "", STATIC, "mobile_scan+code_audit", "plaintext storage"),
    ("insecure data transport", "", STATIC, "code_audit", "cleartext/TLS-verify"),
    # ── Sensitive Data Exposure ──
    ("sensitive data exposure", "disclosure of secrets", STATIC, "secret_scanner+trufflehog_scan", ""),
    ("sensitive data exposure", "sensitive data hardcoded", STATIC, "secret_scanner", ""),
    ("sensitive data exposure", "visible detailed error", STATIC, "code_audit+web_probe", "CA-DEBUG / live debug page"),
    ("sensitive data exposure", "mixed content", DYNAMIC, "web_probe", "WP-MIXED"),
    ("sensitive data exposure", "internal ip disclosure", STATIC, "code_audit", ""),
    ("sensitive data exposure", "", DYNAMIC, "runtime", "token-in-URL/referer observed live"),
    # ── XSS / redirect (static sinks) ──
    ("cross-site scripting", "", STATIC, "code_audit", "CA-XSS sink patterns"),
    ("unvalidated redirects", "open redirect", STATIC, "code_audit", "CA-REDIR"),
    ("unvalidated redirects", "", DYNAMIC, "runtime", ""),
    # ── Server Security Misconfiguration (mostly dynamic, some static) ──
    ("server security misconfiguration", "server-side request forgery", STATIC, "code_audit", "CA-SSRF"),
    ("server security misconfiguration", "path traversal", STATIC, "code_audit", "CA-LFI"),
    ("server security misconfiguration", "unsafe cross-origin", STATIC, "code_audit", "CORS in code"),
    ("server security misconfiguration", "missing secure or httponly", STATIC, "code_audit", "CA-COOKIE"),
    ("server security misconfiguration", "unsafe file upload", DYNAMIC, "runtime", ""),
    ("server security misconfiguration", "misconfigured dns", DYNAMIC, "baddns_scan", "subdomain takeover"),
    ("server security misconfiguration", "lack of security headers", DYNAMIC, "web_probe", "header presence probed live"),
    ("server security misconfiguration", "clickjacking", DYNAMIC, "web_probe", "X-Frame-Options/CSP probed live"),
    ("server security misconfiguration", "fingerprinting", DYNAMIC, "web_probe", "banner disclosure"),
    ("server security misconfiguration", "potentially unsafe http method", DYNAMIC, "web_probe", "OPTIONS Allow"),
    ("server security misconfiguration", "directory listing", DYNAMIC, "web_probe", "auto-index detected live"),
    ("server security misconfiguration", "missing secure or httponly", DYNAMIC, "web_probe", "Set-Cookie flags probed live"),
    ("server security misconfiguration", "", DYNAMIC, "web_probe+wcvs", "headers/TLS/portals live"),
    # ── Network ──
    ("network security misconfiguration", "", DYNAMIC, "gvm_scan", "network service scan"),
    # ── Access control / auth / CSRF (dynamic) ──
    ("broken access control", "", DYNAMIC, "runtime+agent", "IDOR/priv-esc needs live requests"),
    ("broken authentication", "", DYNAMIC, "runtime+agent", "session/2FA behaviour is live"),
    ("cross-site request forgery", "", DYNAMIC, "runtime", "token behaviour is live"),
    ("client-side injection", "", DYNAMIC, "runtime", "binary planting"),
    # ── Config-ability, DoS, components (dynamic/manual) ──
    ("insufficient security configurability", "", DYNAMIC, "runtime", "policy/2FA behaviour"),
    ("application-level denial-of-service", "", DYNAMIC, "runtime", "load-based"),
    ("using components with known", "", DYNAMIC, "gvm_scan+recon", "needs a live version/vuln DB"),
    ("external behavior", "", MANUAL, "-", "browser feature behaviour"),
    ("privacy concerns", "", MANUAL, "-", ""),
    ("indicators of compromise", "", MANUAL, "-", ""),
    # ── Not automatable here ──
    ("automotive", "", OUT, "-", "CAN/RF/ECU hardware"),
    ("physical security", "", OUT, "-", "physical access"),
    ("algorithmic biases", "", OUT, "-", "requires bias evaluation"),
    ("data biases", "", OUT, "-", ""),
    ("developer biases", "", OUT, "-", ""),
    ("societal biases", "", OUT, "-", ""),
    ("misinterpretation biases", "", OUT, "-", ""),
]

# Per-category fallback when no specific rule matched.
_CATEGORY_DEFAULT = {
    "cloud security": (STATIC, "iac_scan"),
    "server-side injection": (STATIC, "code_audit"),
    "cryptographic weakness": (STATIC, "code_audit"),
}


def classify(entry: VrtEntry) -> Coverage:
    cat = entry.category.lower()
    name = entry.name.lower()
    for c_sub, n_sub, method, det, note in _SPECIFIC:
        if c_sub in cat and (not n_sub or n_sub in name):
            return Coverage(method, det, note)
    if cat in _CATEGORY_DEFAULT:
        m, d = _CATEGORY_DEFAULT[cat]
        return Coverage(m, d)
    return Coverage(MANUAL, "-")


def coverage_report() -> dict:
    entries = load()
    rows = [(e, classify(e)) for e in entries]
    by_method: dict[str, int] = {}
    by_method_sev: dict[str, dict[str, int]] = {}
    for e, cov in rows:
        by_method[cov.method] = by_method.get(cov.method, 0) + 1
        by_method_sev.setdefault(e.severity, {})
        by_method_sev[e.severity][cov.method] = by_method_sev[e.severity].get(cov.method, 0) + 1
    total = len(rows)
    automatable = by_method.get(STATIC, 0) + by_method.get(DYNAMIC, 0)
    return {
        "total": total,
        "byMethod": by_method,
        "bySeverityMethod": by_method_sev,
        "automatablePct": round(100 * automatable / total, 1) if total else 0.0,
        "staticPct": round(100 * by_method.get(STATIC, 0) / total, 1) if total else 0.0,
    }


def entries_for_method(method: str) -> list[tuple[VrtEntry, Coverage]]:
    return sorted(((e, c) for e in load() if (c := classify(e)).method == method),
                  key=lambda t: (severity_rank(t[0].severity), t[0].category))


def _main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Report this platform's VRT coverage.")
    ap.add_argument("--method", choices=[STATIC, DYNAMIC, MANUAL, OUT], help="list rows for a method")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if args.method:
        rows = entries_for_method(args.method)
        if args.json:
            import json
            print(json.dumps([{**e.to_dict(), "detector": c.detector, "note": c.note} for e, c in rows], indent=2))
        else:
            for e, c in rows:
                print(f"  [{e.severity:6}] {e.category} / {e.name} {('/ ' + e.variant) if e.variant else ''}  → {c.detector}")
            print(f"\n{len(rows)} rows detectable via '{args.method}'")
        return 0

    rep = coverage_report()
    if args.json:
        import json
        print(json.dumps(rep, indent=2))
        return 0
    print(f"VRT rows: {rep['total']}")
    print(f"  static:       {rep['byMethod'].get('static', 0)}")
    print(f"  dynamic:      {rep['byMethod'].get('dynamic', 0)}")
    print(f"  manual:       {rep['byMethod'].get('manual', 0)}")
    print(f"  out_of_scope: {rep['byMethod'].get('out_of_scope', 0)}")
    print(f"  automatable (static+dynamic): {rep['automatablePct']}%   static-only: {rep['staticPct']}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
