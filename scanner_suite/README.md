# scanner_suite — Unified Scanner Orchestrator + SARIF

One production entry point over the whole static analysis stack. It runs every
applicable analyser over a target, normalises the results into a single
VRT-tagged, severity-ranked list, and renders them as **text, JSON, or SARIF
2.1.0**.

## What it composes

| Scanner | Covers |
|---------|--------|
| `iac_scan` | Terraform / Docker / K8s / GitHub Actions misconfig (AWS/GCP/Azure) |
| `os_audit` | OS/firmware host hardening + native C/C++ bugs |
| `llm_audit` | OWASP LLM Top 10 (2025) |
| `code_audit` | Web-app SAST (SQLi, RCE, XXE, SSTI, SSRF, XSS, crypto…) |
| `contract_audit` | Solidity smart-contract bugs |
| `secret_scanner` | Hardcoded secrets |
| `binary_audit` | ELF hardening + dangerous imports |

Each analyser is optional: if one is missing or errors, the run degrades with an
error note instead of failing.

## CLI

```bash
# human-readable
python -m scanner_suite path/to/repo

# machine formats
python -m scanner_suite path/to/repo --format json
python -m scanner_suite path/to/repo --format sarif -o report.sarif

# scan several first-party trees at once
python -m scanner_suite src services infra --format sarif -o report.sarif

# CI gate: non-zero exit if any finding at/above the threshold exists
python -m scanner_suite path/to/repo --fail-on high
```

Installed as the `nh-scan` console script (see the root `pyproject.toml`).

## SARIF 2.1.0

[SARIF](https://sariftools.com) is the OASIS-standard interchange format that
GitHub code scanning, Azure DevOps, and most security dashboards consume. Each
finding becomes a SARIF `result` with a `ruleId`, a `level`
(error/warning/note), a physical location, a `security-severity` score, and its
VRT id. To surface results in a repo's **Security → Code scanning** tab:

```yaml
- run: python -m scanner_suite . --format sarif -o nh.sarif --fail-on none
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: nh.sarif }
```

## Programmatic use

```python
from scanner_suite import scan, to_sarif
result = scan("path/to/repo")
print(result.summary)                 # {'total': N, 'bySeverity': {...}, ...}
sarif_doc = to_sarif(result)          # dict, ready to json.dump
```
