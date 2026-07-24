# web_attack — Active Web-Injection Engine

The engine that finds the *main* OWASP vulnerabilities (SQLi, XSS, SSRF, command
injection) plus contact-form abuse and email-header injection on a **live**
target — the class of bugs a passive header scanner (`web_probe`) and a static
source scanner (`code_audit`) both walk right past.

It is the discovery half of active testing; the [`verify`](../verify/README.md)
layer is the confirmation half:

```
seed URL ─▶ Crawler ─▶ AttackSurface ─▶ candidate per (param × class) ─▶ verify oracle ─▶ CONFIRMED
           (find the params)                                            (prove it's real)
```

Only oracle-**confirmed** issues are reported. The engine never reports a payload
it merely sent — a finding means a reflected marker came back raw, a response
slowed under an injected delay, or the server made an out-of-band callback.

## What it does

1. **Crawls** the target (bounded BFS, same-scope only) and extracts every
   injection point: each query parameter and each form field.
2. **Generates candidates** — per-parameter classes get one candidate per
   (injection point × class); SSRF is only tested on URL-taking parameters
   (`?url=`, `?redirect=`, …). Two classes are **form-scoped** instead: form
   abuse is one candidate per POST form, and email-header injection is one per
   email-ish field (`email`, `name`, `subject`, …). Sibling fields are
   co-submitted with plausible benign values so the form validates.
3. **Confirms** each candidate through the verification oracles:

   | Class | Oracle | Proof |
   |-------|--------|-------|
   | SQL injection (blind) | timing → boolean | response scales with `SLEEP(n)`, or TRUE/FALSE divergence |
   | Reflected XSS | reflection | unique marker returned **raw** (encoded ⇒ refuted) |
   | Command injection | timing | response scales with an injected `sleep n` |
   | SSRF | OAST | server makes an out-of-band callback (confidence 1.0) |
   | Contact-form abuse (no rate limiting) | rate-limit | a burst of identical submissions is all accepted, no 429 / CAPTCHA |
   | Email/SMTP header injection | email-header | injected `Bcc:` triggers an out-of-band mail delivery (in-band it can only *refute* — rejected CRLF — or flag a lead) |

## Scope & authorisation

Active injection is **attacking** the target — only legal against hosts you are
authorised to test. The engine is scope-gated end to end: the crawler never
leaves the authorised host, and the verifier refuses out-of-scope candidates
before sending anything. The CLI auto-scopes to the host you name (you authorise
the target by naming it) and fails closed everywhere else.

## Usage

```bash
python -m web_attack --demo                            # offline vulnerable app (no network)
python -m web_attack https://staging.example.com/      # live, authorised target
python -m web_attack https://staging.example.com/ --json --subdomains
```

```python
from web_attack import WebAttackEngine
from verify import ScopeGuard, InMemoryInteractionServer

engine = WebAttackEngine(
    scope=ScopeGuard({"staging.example.com"}, allow_subdomains=True),
    interaction_server=InMemoryInteractionServer(),   # real collaborator in prod (see below)
)
report = engine.run("https://staging.example.com/")
for f in report.findings:
    print(f.severity, f.title, "→", f.method, f.url, f"param={f.param}", "|", f.evidence)
```

## Out-of-band (SSRF / email header injection) in production

SSRF and email-header-injection *confirmation* both need an interaction server —
SSRF an HTTP/DNS collaborator, email-header injection a mail-receiving one. Tests
and `--demo` use the in-memory one; in production, pass a real collaborator
implementing `verify.InteractionServer` (e.g. a self-hosted interactsh). Without
one, those candidates are reported as **inconclusive**, never guessed — so the
CLI omits them by default rather than pretend. Contact-form abuse (rate limiting)
is confirmed fully in-band and needs no collaborator, so it works on any live
target.

## Honest scope

- It confirms the injectable classes above. Stored XSS, second-order SQLi,
  authenticated-only surface (behind a login), business logic, and CSRF need a
  session model / multi-step flows and are out of scope for this first engine.
- Time-based confirmation is inherently slower than a passive scan (it waits for
  the injected delay). That's the cost of *proof* over a guess.
- It discovers the **unauthenticated** surface reachable from the seed. Feed it
  authenticated cookies (via a future auth-session option) to reach more.
