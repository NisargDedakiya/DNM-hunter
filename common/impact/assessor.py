"""Vulnerability impact assessment: CVSS + tech-stack, LLM-grounded.

Combines the two deterministic pieces — the CVSS v3.1 calculator and the
tech-stack contextual adjuster — into one assessment, then builds a *grounding
prompt* so the platform's already-configured LLM can write the impact narrative
from facts rather than from memory.

Design decision (important): this does NOT train or fine-tune a model. CVSS is
deterministic math and CVE data is retrieval, so the reliable score is computed
here; the LLM is used only to *explain* that computed result in the target's
context — Retrieval-Augmented Generation, not training. The narrate() function
takes any callable `llm(prompt) -> str` (e.g. a LangChain model built by
agentic/orchestrator_helpers/llm_setup.py), so it stays provider-agnostic and
unit-testable with a stub.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from .cvss import base_score as cvss_base_score, severity_rating, InvalidVector
from .tech_impact import ExposureContext, assess_contextual_impact, ContextualImpact


@dataclass
class ImpactAssessment:
    vuln_category: str
    cvss_vector: Optional[str]
    contextual: ContextualImpact
    cve_ids: list[str] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)
    narrative: str = ""     # filled in by narrate() when an LLM is available

    def to_dict(self) -> dict:
        return {
            "vulnCategory": self.vuln_category,
            "cvssVector": self.cvss_vector,
            "cveIds": self.cve_ids,
            "techStack": self.tech_stack,
            "narrative": self.narrative,
            **self.contextual.to_dict(),
        }


def assess(
    vuln_category: str,
    cvss_vector: Optional[str] = None,
    cvss_score: Optional[float] = None,
    tech_stack: Optional[list[str]] = None,
    exposure: Optional[ExposureContext] = None,
    cve_ids: Optional[list[str]] = None,
) -> ImpactAssessment:
    """Assess a finding's impact. Provide EITHER a CVSS vector (preferred — the
    score is computed from it) OR a raw score. If neither is given, a
    category-based default base score is used so an assessment is always
    produced."""
    if cvss_vector:
        try:
            base = cvss_base_score(cvss_vector).base_score
        except InvalidVector:
            base = cvss_score if cvss_score is not None else _default_base(vuln_category)
    elif cvss_score is not None:
        base = max(0.0, min(10.0, float(cvss_score)))
    else:
        base = _default_base(vuln_category)

    contextual = assess_contextual_impact(vuln_category, base, tech_stack, exposure)
    return ImpactAssessment(
        vuln_category=vuln_category,
        cvss_vector=cvss_vector,
        contextual=contextual,
        cve_ids=cve_ids or [],
        tech_stack=tech_stack or [],
    )


# Conservative category baselines when no CVSS data exists at all (worst-case
# leaning so nothing is silently under-rated; refined the moment a vector or
# NVD score arrives).
_DEFAULT_BASE = {
    "rce": 9.8, "command injection": 9.8, "deserialization": 9.8,
    "sqli": 8.8, "sqli_exploitation": 8.8, "ssrf": 8.6, "xxe": 8.2,
    "idor": 6.5, "bola": 6.5, "idor_bola_exploitation": 6.5,
    "xss": 6.1, "xss_exploitation": 6.1, "open redirect": 4.3, "cors": 5.4,
    "path_traversal": 7.5, "information_disclosure": 5.3, "jwt": 7.5,
}


def _default_base(vuln_category: str) -> float:
    return _DEFAULT_BASE.get((vuln_category or "").lower().strip(), 5.0)


def build_grounding_prompt(assessment: ImpactAssessment, finding_summary: str = "") -> str:
    """Build the prompt that grounds the LLM in the computed facts. The model is
    asked to explain, not to score — the numbers are fixed inputs."""
    c = assessment.contextual
    factor_lines = "\n".join(
        f"  - [{'+' if f.direction == 'up' else '-'}{f.weight}] {f.name}: {f.rationale}"
        for f in c.factors
    ) or "  (no stack/exposure modifiers)"
    return (
        "You are a senior application-security analyst. Using ONLY the facts below, write a "
        "concise, concrete impact assessment for this finding. Do NOT invent a different score — "
        "the CVSS numbers are computed and fixed. Explain what an attacker could actually achieve "
        "on THIS target given its technology stack, and who/what is affected.\n\n"
        f"Vulnerability class: {assessment.vuln_category}\n"
        f"Finding: {finding_summary or '(summary not provided)'}\n"
        f"Related CVEs: {', '.join(assessment.cve_ids) or 'none'}\n"
        f"Detected tech stack: {', '.join(assessment.tech_stack) or 'unknown'}\n"
        f"CVSS base score: {c.base_score} ({c.base_severity})"
        f"{f' — vector {assessment.cvss_vector}' if assessment.cvss_vector else ''}\n"
        f"Tech-stack/exposure-adjusted score: {c.contextual_score} ({c.contextual_severity})\n"
        f"Contextual factors that moved the score:\n{factor_lines}\n\n"
        "Write 3-5 sentences: (1) concrete attacker capability on this stack, (2) data/systems at "
        "risk, (3) why the contextual score differs from the base score, (4) the single most "
        "important remediation. Be specific to the stack; avoid generic boilerplate."
    )


def narrate(
    assessment: ImpactAssessment,
    llm: Callable[[str], str],
    finding_summary: str = "",
) -> ImpactAssessment:
    """Fill assessment.narrative using a provided `llm(prompt) -> str` callable.
    Never raises on LLM failure — a failed narration leaves the deterministic
    assessment intact (the score is what matters; the prose is a bonus)."""
    try:
        assessment.narrative = (llm(build_grounding_prompt(assessment, finding_summary)) or "").strip()
    except Exception:
        assessment.narrative = ""
    return assessment
