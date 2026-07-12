"""Recon planner (master-plan Phase 3, Priority 2).

Given a program's detected technologies and enumerated attack surface, produces
a structured RECON PLAN *before* anything runs. Two hard rules make it
trustworthy rather than a tool-launcher:

1. Every step references a module that actually exists — the planner only ever
   emits ``module_name`` values it found in the ModuleRegistry (Phase 2).
2. It is technology-aware — modules whose ``tech_affinity`` matches a detected
   technology are prioritized (e.g. a Terraform repo surfaces iac_scan first).

The plan is deterministic given the same inputs, so it is fully unit-testable.
An LLM can later enrich the ``reasoning`` narrative, but the *structure* and the
module selection never depend on a model being available.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .module_contract import ModuleCategory, ModuleMetadata
from .module_registry import ModuleRegistry, default_registry


@dataclass
class PlanStep:
    module_name: str
    rationale: str
    target_assets: list[str]
    priority: str                       # high | medium | low
    estimated_value: str

    def to_dict(self) -> dict:
        return {
            "moduleName": self.module_name,
            "rationale": self.rationale,
            "targetAssets": self.target_assets,
            "priority": self.priority,
            "estimatedValue": self.estimated_value,
        }


@dataclass
class ReconPlan:
    steps: list[PlanStep] = field(default_factory=list)
    reasoning: str = ""

    def to_dict(self) -> dict:
        return {"steps": [s.to_dict() for s in self.steps], "reasoning": self.reasoning}


_PRIORITY_RANK = {"high": 0, "medium": 1, "low": 2}


class ReconPlanner:
    def __init__(self, registry: ModuleRegistry = default_registry) -> None:
        self.registry = registry

    def build_plan(
        self,
        detected_tech: Optional[list[str]] = None,
        assets: Optional[list[str]] = None,
        include_categories: Optional[list[ModuleCategory]] = None,
    ) -> ReconPlan:
        detected = [t.strip().lower() for t in (detected_tech or []) if t.strip()]
        target_assets = assets or []

        modules = self.registry.all()
        if include_categories:
            wanted = set(include_categories)
            modules = [m for m in modules if m.metadata().category in wanted]

        steps: list[PlanStep] = []
        for module in modules:
            meta = module.metadata()
            matched = self._matched_tech(meta, detected)
            priority = self._priority_for(meta, matched, detected)
            steps.append(PlanStep(
                module_name=meta.name,
                rationale=self._rationale(meta, matched),
                target_assets=target_assets,
                priority=priority,
                estimated_value=self._estimated_value(meta),
            ))

        # Stable ordering: priority first, then recon before scanners, then name.
        steps.sort(key=lambda s: (
            _PRIORITY_RANK.get(s.priority, 3),
            0 if self._is_recon(s.module_name) else 1,
            s.module_name,
        ))

        return ReconPlan(steps=steps, reasoning=self._overall_reasoning(detected, steps))

    # ── helpers ──
    def _matched_tech(self, meta: ModuleMetadata, detected: list[str]) -> list[str]:
        affinity = {t.strip().lower() for t in meta.tech_affinity}
        return [t for t in detected if t in affinity]

    def _priority_for(self, meta: ModuleMetadata, matched: list[str], detected: list[str]) -> str:
        if matched:
            return "high"
        # Broad recon is always worth running even with no tech signal.
        if meta.category == ModuleCategory.RECON:
            return "medium"
        # A scanner with no matching tech signal is lower priority — run it only
        # once recon has surfaced something for it to act on.
        return "low" if detected else "medium"

    def _is_recon(self, module_name: str) -> bool:
        m = self.registry.get(module_name)
        return bool(m and m.metadata().category == ModuleCategory.RECON)

    def _rationale(self, meta: ModuleMetadata, matched: list[str]) -> str:
        if matched:
            return f"Detected {', '.join(matched)} — {meta.display_name} is tuned for this stack."
        if meta.category == ModuleCategory.RECON:
            return f"{meta.display_name} broadens the attack surface before targeted scanning."
        return f"{meta.display_name} runs once recon surfaces relevant targets."

    def _estimated_value(self, meta: ModuleMetadata) -> str:
        return {
            ModuleCategory.RECON: "attack-surface expansion (assets, endpoints, params)",
            ModuleCategory.SCANNER: "confirmed vulnerabilities / exposures",
            ModuleCategory.VALIDATOR: "confidence + false-positive filtering",
            ModuleCategory.REPORTER: "reportable output",
            ModuleCategory.EXPORT: "exported artifacts",
        }.get(meta.category, "findings")

    def _overall_reasoning(self, detected: list[str], steps: list[PlanStep]) -> str:
        high = [s.module_name for s in steps if s.priority == "high"]
        if detected:
            lead = f"Technology signals ({', '.join(sorted(set(detected)))}) drive prioritization. "
        else:
            lead = "No technology signals yet — leading with broad recon to build the attack surface. "
        focus = f"Prioritized first: {', '.join(high)}." if high else "Running recon before targeted scanners."
        return lead + focus
