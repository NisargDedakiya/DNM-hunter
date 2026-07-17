# NisargHunter AI — Security Scanner Architecture

The platform's detection capability is a suite of independent, composable
analysers, each mapped to the **Bugcrowd VRT** and unified behind one
orchestrator with standard (SARIF) output.

## Layers

```
                         ┌──────────────────────────────┐
   nh-scan CLI  ───────► │        scanner_suite         │  text / JSON / SARIF 2.1.0
   (CI, users)           │  orchestrator + SARIF export │  + CI exit-code gate
                         └───────────────┬──────────────┘
                                         │ composes
        ┌───────────────┬────────────────┼────────────────┬────────────────┐
        ▼               ▼                ▼                ▼                ▼
    STATIC (source / config / binary)                          DYNAMIC (live target)
  ┌──────────┐  ┌──────────┐  ┌────────────┐  ┌────────────┐   ┌──────────┐
  │code_audit│  │ iac_scan │  │  os_audit  │  │contract_…  │   │web_probe │
  │  (SAST)  │  │ (cloud)  │  │(OS/firmware│  │ (Solidity) │   │  (DAST)  │
  └──────────┘  └──────────┘  └────────────┘  └────────────┘   └──────────┘
  ┌──────────┐  ┌──────────┐  ┌────────────┐  ┌────────────┐   ┌──────────┐
  │llm_audit │  │binary_…  │  │ deep_binary│  │secret_scan │   │ gvm/wcvs │
  │(LLM Top10│  │  (ELF)   │  │  (angr)    │  │            │   │ baddns…  │
  └──────────┘  └──────────┘  └────────────┘  └────────────┘   └──────────┘
                                         │
                                         ▼
                              ┌──────────────────────┐
                              │   vrt (taxonomy +     │  every finding → canonical
                              │   coverage map)       │  VRT id + severity
                              └──────────────────────┘
```

## Modules

| Module | Tier | Detects | Output ids |
|--------|------|---------|-----------|
| `code_audit` | static | SQLi, RCE/cmd-inj, XXE, LFI, SSTI, SSRF, XSS, LDAP, CRLF, open-redirect, weak crypto, insecure deserialization, insecure RNG | VRT + CWE |
| `contract_audit` | static | reentrancy, tx.origin, unchecked call, delegatecall, selfdestruct, owner takeover, integer overflow | VRT + SWC |
| `llm_audit` | static | OWASP LLM Top 10 (2025) | LLMxx |
| `iac_scan` | static | Terraform/Docker/K8s/GHA misconfig (AWS/GCP/Azure) | rule ids |
| `os_audit` | static | host hardening (sshd/sudoers/sysctl), native C/C++ bugs | rule ids |
| `binary_audit` | static | ELF hardening (NX/PIE/RELRO/canary/FORTIFY), dangerous imports | BIN-* |
| `deep_binary` | static | symbolic execution — reach-target, control-flow hijack (angr) | — |
| `secret_scanner` | static | hardcoded secrets/keys | SECRET-* |
| `web_probe` | dynamic | security headers, cookie flags, CORS, unsafe methods, clickjacking, banner/dir-listing/debug/mixed-content | WP-* |
| `vrt` | meta | full Bugcrowd VRT + honest coverage map | VRT ids |

## Design principles

- **Pure, testable cores.** Detection logic is separated from I/O — e.g.
  `web_probe.analyze_response(...)` and `code_audit.scan_code(...)` are pure
  functions, unit-tested with synthetic inputs; the network/filesystem wrappers
  are thin. 103 Python tests cover the suite.
- **Precision over recall where it counts.** Injection sinks fire on
  taint-tracked user input, not constants; parameterised queries and guarded
  contracts are not flagged.
- **Honest coverage.** `vrt` classifies every one of the ~400 VRT rows as
  static / dynamic / manual / out-of-scope and ties it to the real detector.
  Nothing is claimed that isn't backed by code (`python -m vrt.coverage`).
- **Standard output.** SARIF 2.1.0 makes the suite a drop-in for GitHub code
  scanning and other dashboards.
- **Graceful degradation.** A missing optional dependency (angr, hcl2) disables
  one analyser, never the whole run.

## Quality gates (CI)

`.github/workflows/ci.yml` runs on every push/PR:

1. **Python** — `ruff check` (lint) + `pytest` (the scanner suite).
2. **Web app** — `npm run type-check` + `vitest run`.
3. **SARIF report** — `nh-scan` over the benchmark fixtures, uploaded as an
   artifact (the integration point for real code-scanning uploads).

## Running locally

```bash
pip install -e ".[dev,iac]"      # editable install with dev + IaC extras
nh-scan path/to/target --format sarif -o report.sarif --fail-on high
python -m vrt.coverage           # coverage snapshot across the VRT
pytest                           # full suite
ruff check                       # lint
```
