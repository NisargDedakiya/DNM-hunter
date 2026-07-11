"""Pydantic models and TypedDict state for triage agent."""

from typing import TypedDict, Optional
from pydantic import BaseModel


class TriageFinding(BaseModel):
    title: str
    description: str
    severity: str = "medium"
    priority: int = 0
    category: str = "vulnerability"
    remediation_type: str = "code_fix"
    affected_assets: list = []
    cvss_score: Optional[float] = None
    cve_ids: list[str] = []
    cwe_ids: list[str] = []
    capec_ids: list[str] = []
    evidence: str = ""
    attack_chain_path: str = ""
    exploit_available: bool = False
    cisa_kev: bool = False
    solution: str = ""
    fix_complexity: str = "medium"
    estimated_files: int = 0
    target_repo: str = ""
    target_branch: str = "main"

    # ── AI validator (Phase 09) — confidence/impact scoring on top of the
    # weighted triage priority above. The triage LLM self-assesses how
    # confident it is that this is a true positive vs. a false alarm, so
    # operators can triage "needs_manual_review" findings first instead of
    # reading every one at the same priority.
    confidence_score: Optional[float] = None       # 0-100, likelihood true positive
    false_positive_score: Optional[float] = None   # 0-100
    business_impact: str = ""
    likelihood: str = ""                            # "low" | "medium" | "high"
    validator_status: str = "needs_manual_review"
    # confirmed | likely | needs_manual_review | ignored

    # ── AI Reasoning (Phase 16) — links this remediation back to the
    # ChainFinding(s) (chain_findings context, cypher_queries.py) it was
    # synthesized from, so the webapp can look up the originating
    # ChainStep's tool_name/reasoning/thought and answer "why this tool,
    # why this payload, why this endpoint" — not just the validator's
    # confidence assessment on top of it. Empty when this remediation
    # wasn't derived from a specific attack-chain finding (e.g. a DAST/CVE
    # correlation with no chain involved) — that's expected, not an error.
    source_finding_ids: list[str] = []


class RemediationDraft(BaseModel):
    findings: list[TriageFinding] = []
    summary: str = ""
    by_severity: dict[str, int] = {}
    by_type: dict[str, int] = {}


class TriageState(TypedDict):
    user_id: str
    project_id: str
    session_id: str
    settings: dict
    raw_data: dict
    analysis_result: Optional[RemediationDraft]
    status: str  # initializing, collecting, analyzing, saving, complete, error
    current_phase: str
    error: Optional[str]
