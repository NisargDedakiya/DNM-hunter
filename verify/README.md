# verify — Oracle-Backed Verification Layer

The difference between DNM-Hunter and a plain scanner is that a finding is not
reported until a **deterministic oracle** has confirmed it against the live
target. The AI/scanner **proposes** what to test; the oracle **decides** whether
it's real, purely from observable evidence. No model output is ever treated as a
verdict — that's what stops the "confident hallucination" failure mode where an
LLM says "yes, exploited" about something it made up.

```
   scanner / AI  ──▶  Candidate  ──▶  ScopeGuard  ──▶  Oracle  ──▶  Verdict + Evidence
  (proposes what)                   (is it authorised?)   (is it real?)
```

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `confirmed` | an oracle deterministically proved exploitability |
| `refuted` | an oracle proved it is **not** exploitable (a false positive caught) |
| `inconclusive` | no oracle could decide — needs a different signal or manual review |
| `skipped` | not attempted (out of authorised scope, or no oracle for the class) |

## Oracles

| Oracle | Classes | How it proves it | Confidence |
|--------|---------|------------------|-----------|
| `TimingOracle` | blind SQLi, blind command injection | response time scales with an injected `SLEEP(n)`/`sleep n` | 0.90 |
| `BooleanOracle` | boolean-blind SQLi | TRUE condition matches baseline, FALSE diverges | 0.85 |
| `ReflectionOracle` | reflected XSS | a unique marker returns **raw** (not HTML-encoded); encoded ⇒ `refuted` | 0.80 |
| `OastOracle` | SSRF, blind RCE | the target makes an **out-of-band callback** to attacker-controlled infra | **1.00** |
| `DifferentialOracle` | IDOR, BOLA, BFLA | an *unauthorised* identity receives the owner's protected response | 0.90 |

An out-of-band callback is the strongest possible proof — the server literally
reached out and touched a host we control — so it scores 1.0. Everything else is
strong but in-band and caps lower.

## The scope gate (non-negotiable)

Verification is **active testing** — it sends live payloads and solicits
callbacks. That is only lawful against targets you are authorised to test.
`ScopeGuard` makes authorisation an enforced precondition and **fails closed**:
an empty allowlist authorises nothing, and any out-of-scope target returns
`skipped` **before a single request is sent**.

```python
from verify import VerificationEngine, ScopeGuard, Candidate, VulnClass, InMemoryInteractionServer

engine = VerificationEngine(
    scope=ScopeGuard({"staging.example.com"}, allow_subdomains=True),
    interaction_server=InMemoryInteractionServer(),   # swap for a real collaborator in prod
)
result = engine.verify(Candidate(
    vuln_class=VulnClass.BLIND_SQLI,
    target="https://staging.example.com/item",
    param="id", base_value="1", source_rule="CA-SQLI",
))
print(result.verdict, result.confidence, result.evidence)
```

## Out-of-band (OAST) in production

`OastOracle` needs an interaction server. Tests and the demo use the built-in
`InMemoryInteractionServer` (deterministic, offline). In production, implement the
`InteractionServer` protocol against a real collaborator (e.g. a self-hosted
[interactsh](https://github.com/projectdiscovery/interactsh) instance):

```python
class InteractshServer:            # implements verify.InteractionServer
    def register(self) -> tuple[str, str]: ...   # -> (token, callback_domain)
    def poll(self, token: str) -> list[Interaction]: ...
```

## Demo

```bash
python -m verify          # or: nh-verify-demo
```

Runs every oracle against a built-in simulated target so you can see a
`confirmed` / `refuted` / `skipped` verdict and its evidence — no network, no live
host.

## Honest scope

- This layer **confirms** what a detector proposed; it does not discover new
  injection points on its own (the scanner/recon layer feeds it candidates).
- `TimingOracle` returns `inconclusive`, never `refuted`, when no delay is seen —
  absence of a timing signal doesn't prove safety (could be a WAF or a different
  injection type). Only the reflection and differential oracles can `refute`.
- Business-logic abuse, rate-limiting and design flaws have no deterministic
  single-request oracle and are out of scope here — they belong to the agentic /
  manual workflow.
