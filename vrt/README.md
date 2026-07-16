# vrt — Bugcrowd VRT Taxonomy + Honest Coverage Map

Loads the full Bugcrowd **Vulnerability Rating Taxonomy** (~400 rows,
`taxonomy.tsv`) as first-class data so every finding the platform produces can
be rolled up to a canonical VRT category and severity — and so the platform can
report, truthfully, which VRT rows it can and cannot detect.

## Two questions it answers

1. **Canonical severity/category for a finding** — `vrt.lookup(category, name, variant)`.
2. **How can this platform detect this row?** — `vrt.classify(entry)` returns one of:
   - `static` — a shipped static analyser finds it from source/config/binary
     (`code_audit`, `contract_audit`, `iac_scan`, `os_audit`, `binary_audit`,
     `mobile_scan`, `llm_audit`, `secret_scanner`).
   - `dynamic` — only findable against a **live target** by a runtime scanner or
     the agent (`gvm_scan`, `wcvs`, `baddns_scan`, `cloud_recon`,
     `ai_attack_surface_scan`, the pentest agent).
   - `manual` — needs a human, economic-logic review, or side-channel work
     (DeFi accounting, ZK circuits, crypto side-channels, browser behaviour).
   - `out_of_scope` — hardware/automotive/RF/physical and algorithmic-bias rows
     that no software in this repo can assess.

The `static` mapping is keyed on **real detector rule namespaces**, so the
coverage numbers reflect code that exists, not aspiration.

## Coverage snapshot

```
$ python -m vrt.coverage
VRT rows: 402
  static:       140
  dynamic:      172
  manual:        47
  out_of_scope:  43
  automatable (static+dynamic): 77.6%   static-only: 34.8%
```

List the rows for any method:

```bash
python -m vrt.coverage --method static --json
python -m vrt.coverage --method out_of_scope
```

## Why this matters

"Find every vulnerability in the VRT" is not honestly achievable by any tool —
a large part of the taxonomy is hardware, physical, live-only, or human-judgment
work. This module makes the platform's true reach explicit and auditable instead
of implied: it says exactly which rows a scan can find statically, which need a
live target, and which it will never find automatically.
