# report_gen — Professional Report Generation

Turns raw scanner findings into a **submission-ready report** — the deliverable a
bug hunter attaches to a bounty submission or a pentester hands to a client.

Every finding is enriched with:

- **CVSS v3.1** base score + vector (computed by `common.impact.cvss`, so the
  displayed severity and the score always agree — no "High, CVSS 9.8").
- **Classification** — its Bugcrowd **VRT** id and **CWE**.
- **Verification / reproduction** — the concrete next step a hunter takes to
  confirm the issue (payloads, techniques, tools).
- **Remediation** — the fix.
- **References** — CWE / OWASP / SWC / spec links.

Guidance is curated per rule family (`report_gen/knowledge.py`) for the injection,
crypto, smart-contract, and dynamic rules, with a severity-shaped fallback so
every finding still gets a usable writeup.

## Output formats

| Format | Use |
|--------|-----|
| Markdown (`to_markdown`) | bounty submissions, GitHub issues, ticket bodies |
| HTML (`to_html`) | client-deliverable — self-contained, printable, light/dark, no external assets |

## CLI

```bash
# Markdown report to stdout
nh-scan path/to/target --format md

# Client HTML report to a file
nh-scan path/to/target --format html -o report.html
```

## Programmatic

```python
from scanner_suite import scan
from report_gen import build_report, to_markdown, to_html

report = build_report(scan("path/to/target"), title="Acme Corp — Web Assessment")
open("report.md", "w").write(to_markdown(report))
open("report.html", "w").write(to_html(report))
```

`build_report` accepts anything with `.findings` (and optional `.target` /
`.errors`), so it works with a `SuiteResult`, a single scanner's output wrapped
in a small shim, or `web_probe` findings.

## Honest note

The report is an analyst *aid*, not a substitute for verification. Findings come
from automated static/dynamic analysis; the CVSS scores are rule-level defaults
(adjust per real environmental/temporal context), and every finding should be
manually reproduced before it is submitted or signed off. The report footer says
so explicitly.
