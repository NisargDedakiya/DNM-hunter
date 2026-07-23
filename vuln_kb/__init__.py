"""vuln_kb — the platform's vulnerability knowledge base.

One machine-readable spec per vulnerability class: what it is, how to detect it,
what evidence to collect, how to verify it (which oracle), its CWE/OWASP/CAPEC/VRT
mapping, remediation and which DNM engine covers it — plus a risk-scoring
composite. The AI agent reads it to know what to build and how to confirm; the
report generator reads it to enrich findings.

    from vuln_kb import get, all_vulns, compose_risk
    v = get("sqli")
    print(v.name, v.cwe, v.verify.method)          # SQL Injection CWE-89 timing
    compose_risk("critical", confidence="firm", exploit_verified=True)
"""

from .knowledge import KB, Verify, Vuln, all_vulns, compose_risk, get

__all__ = ["Vuln", "Verify", "KB", "get", "all_vulns", "compose_risk"]
