# vuln_kb — Vulnerability Knowledge Base

The single source of truth for every vulnerability class the platform hunts. It's
what makes DNM-Hunter's AI *understand* a vulnerability instead of just matching a
string: for each class it records **what it is → how to detect it → what evidence
to collect → how to VERIFY it (which oracle) → CWE / OWASP / CAPEC / VRT →
severity → impact → remediation → references → which DNM engine covers it.**

This is the connective tissue between the detectors (`code_audit` `CA-*`,
`mobile_audit` `MA-*`, `llm_audit` `LLM-*`), the verification oracles
([`verify`](../verify/README.md)), the OWASP map ([`vrt.owasp`](../vrt)) and the
report generator.

## Classes covered

SQL Injection · NoSQL Injection · XSS · IDOR · SSRF · OS Command Injection · XXE ·
SSTI · Path Traversal/LFI · Open Redirect · Authentication Failures · JWT Problems ·
File Upload · API Security (BOLA/BFLA/BOPLA) · Mass Assignment · Business Logic ·
CSRF · Cryptographic Failures.

Every entry maps to the exact schema you asked for:

| Field | Example (SQL Injection) |
|-------|--------------------------|
| Name / Category | SQL Injection / Server-Side Injection |
| Severity · CWE · OWASP · CAPEC · VRT | critical · CWE-89 · A03/API8 · CAPEC-66 · `server_side_injection.sql_injection` |
| Where | URL params, POST body, JSON, cookies, headers |
| Payloads | `'`, `1' OR '1'='1`, `1 AND SLEEP(5)`, `UNION SELECT` |
| Evidence | SQL error, time delay, boolean divergence, extracted rows |
| **Verify** | **`timing`** → `verify.TimingOracle` (response time scales with an injected delay) |
| Engines | `code_audit CA-SQLI`, `mobile_audit MA-SQLI`, `web_attack` timing/boolean oracle |
| Remediation | Parameterised queries; least-privilege DB user |

## Usage

```bash
python -m vuln_kb              # list every class
python -m vuln_kb sqli         # full spec for one class (accepts names/aliases)
python -m vuln_kb "jwt problems" --json
```

```python
from vuln_kb import get, all_vulns, compose_risk

v = get("ssrf")
print(v.verify.method, v.cwe, v.owasp_web)     # oast CWE-918 A10
print(v.remediation)

# Risk Scoring Engine — blend severity + confidence + verification (+ optional EPSS)
compose_risk("critical", confidence="heuristic")                       # a lead
compose_risk("critical", confidence="heuristic", exploit_verified=True) # oracle-confirmed → higher
```

## Risk scoring

`compose_risk()` is the composite the platform uses instead of a bare label. It
blends **base severity × confidence**, gives a **bump when an oracle actually
verified the exploit** (a proven finding outranks a lead of the same severity),
and accepts an optional **EPSS** probability from a live feed. It returns a 0–10
score, a band, and the factors that produced it — so the number is explainable.

## Honesty built in

A unit test enforces that the KB never points at something that doesn't exist:
every OWASP id, every `CA-*/MA-*/LLM-*` rule and every verification method it
names is checked against the real `vrt.owasp` map, the scanner sources and the
`verify` oracle set. If a detector is renamed or removed, the KB test fails until
the KB is corrected — so the "which engine covers this" column can't drift into
fiction.

The `verify` method on each class is honest about reach: `timing` / `reflection` /
`oast` / `differential` / `boolean` classes have a deterministic oracle;
`static` classes are confirmed from source; `manual` classes (business logic, file
upload, auth flows) need a session, a multi-step flow, or human judgement — no
single-request oracle proves them, and the KB says so.
