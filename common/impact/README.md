# Impact assessment engine (CVSS + tech-stack, LLM-grounded)

Answers *"how bad is this vulnerability **on this target**?"* — combining a
deterministic CVSS score with tech-stack-aware context, and letting the
platform's existing LLM narrate the result from facts.

## Design decision: grounding, not training

This deliberately does **not** train or fine-tune a model on CVE/CVSS data.
That would be the wrong tool:

- **CVSS is deterministic math**, not a prediction — [`cvss.py`](cvss.py)
  encodes the official FIRST.org v3.1 formula, so a vector always yields the
  exact published score (validated against Log4Shell → 10.0, and other
  reference vectors). A model that "remembers" scores would be less accurate,
  not more.
- **CVE data is retrieval**, not generation — the existing
  `recon/helpers/cve_helpers.py` already fetches NVD/Vulners data.
- The **LLM's job is explanation** — [`assessor.py`](assessor.py) builds a
  *grounding prompt* containing the computed CVSS, the detected stack, and the
  contextual factors, and asks the model to explain the impact **without
  changing the numbers**. This is Retrieval-Augmented Generation, and it reuses
  whatever provider the operator configured (via
  `agentic/orchestrator_helpers/llm_setup.py`) — no new model, no training run.

## The three pieces

| Module | What it does | ML? |
|---|---|---|
| [`cvss.py`](cvss.py) | CVSS v3.1 vector → base score + severity (exact spec) | No — pure math |
| [`tech_impact.py`](tech_impact.py) | Adjusts the score for the target's stack + exposure, with an explicit rationale per factor | No — explainable rules |
| [`assessor.py`](assessor.py) | Combines both; builds the LLM grounding prompt; `narrate()` fills the prose via any `llm(prompt)->str` | LLM used only to explain |

## Why tech-stack context matters

The same bug is not equally dangerous everywhere. The engine makes that
concrete — e.g. an identical SSRF (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`,
base **7.5 High**):

- on a static nginx site → **8.6 High**
- on an **AWS-hosted** app handling sensitive data → **10.0 Critical**, because
  SSRF there can reach the instance metadata service and steal IAM credentials.

Every adjustment is logged as a factor with a rationale, so the score is
auditable and defensible in a report.

## Usage

```python
from common.impact.assessor import assess, narrate
from common.impact.tech_impact import ExposureContext
from agentic.orchestrator_helpers.llm_setup import build_llm   # existing provider

a = assess(
    "ssrf",
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    tech_stack=["aws", "ec2", "python"],
    exposure=ExposureContext(internet_facing=True, cloud_hosted=True, handles_sensitive_data=True),
    cve_ids=["CVE-2024-XXXX"],
)
print(a.contextual.contextual_score, a.contextual.contextual_severity)   # 10.0 Critical

# optional narrative from the configured LLM (grounded in the computed facts)
model = build_llm(...)
narrate(a, lambda prompt: model.invoke(prompt).content, finding_summary="SSRF via /api/download")
print(a.narrative)
```

## Wiring into the platform (next step)

The natural home is the AI validator (`agentic/cypherfix_triage/`), which already
produces `cvssScore` + `businessImpact` on each remediation: run `assess()` with
the finding's CVSS vector + the program's `ProgramMemory.techStack`, store
`contextualScore` alongside the base score, and use `narrate()` for the
`businessImpact` prose. The webapp can then show base-vs-contextual severity on
the remediation detail (next to the existing AI Reasoning panel).

## Tests

```bash
python -m unittest common.impact.tests.test_impact -v   # 14 tests
```
