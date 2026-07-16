# GitHub Repo Scanner

Give it a **GitHub repo link** (URL or `owner/name`) and it finds vulnerabilities
in the repository — hardcoded secrets and IaC/DevOps misconfigurations — with
severity scoring and secret redaction.

It **composes existing detectors** rather than reimplementing them:

| Stage | Reuses |
|---|---|
| Shallow clone | `iac_scan/git_source.py :: clone_repo` |
| IaC/DevOps misconfig (Docker, Compose, K8s, GitHub Actions, Terraform) | `iac_scan/runner.py :: IacScanRunner` |
| Value-pattern secret detection (100+ providers: AWS, GitHub, Stripe, GCP, Slack, …) | `recon/helpers/js_recon/patterns.py :: JS_SECRET_PATTERNS` |

## Usage

```bash
# CLI
python -m repo_scan https://github.com/owner/name
python -m repo_scan owner/name --json
python -m repo_scan ./local/checkout        # scan a local path, no clone

# library
from repo_scan import scan_repo
res = scan_repo("https://github.com/owner/name", token=None)   # token for private repos
print(res.summary)          # {'total': N, 'bySeverity': {...}, 'highestSeverity': 'critical'}
for f in res.findings:
    print(f.severity, f.kind, f.file, f.title)
```

`scan_tree(path)` runs every detector over an already-checked-out directory —
fully offline and deterministic, which is how the tests exercise it.

## Safety

- **Secrets are redacted** before they leave the scanner (`AKIA…ZC (20 chars)`),
  so a raw credential is never stored or displayed.
- **Placeholders are ignored** (`AKIAEXAMPLE…`, `your_key`, `changeme`, `<...>`)
  to keep precision high.
- **Overlapping matches collapse** — one leaked value that matches several
  provider patterns is one finding (highest severity), not N.
- Vendored/binary noise is skipped (`node_modules`, `.git`, `vendor`, `dist`,
  images, archives, minified JS).
- Only scan repositories that are **in the engagement's declared scope**.

## Product integration

Shipped as a plugin: `plugins/scanner/repo-scan.json` (visible in the
Marketplace, permissions declared). The natural workflow tie-in is a program's
`github` **asset** — point the scanner at that repo URL. The recon_orchestrator
can expose it as `POST /repo-scan/start` (it already runs the underlying
iac_scan + secret patterns in its containers); `python -m repo_scan` is the
runnable interface today.

## Tests

```bash
python -m unittest repo_scan.tests.test_repo_scan -v   # 8 tests, offline
```
