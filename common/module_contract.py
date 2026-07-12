"""The unified module contract (master-plan Phase 2, Priority 6).

Every scanning/recon module in NisargHunter AI — recon, gvm_scan,
github_secret_hunt, trufflehog_scan, iac_scan, cloud_recon,
ai_attack_surface_scan — is described, executed, and tracked through the SAME
lifecycle contract:

    Metadata -> Configuration -> Execution -> Result -> Validation -> Report -> Logs

This module defines the data shapes for each stage plus the ``ModuleContract``
abstract base. Adapters (see ``common/adapters/``) implement this base by
delegating to a module's existing entrypoint — they wrap, they do not rewrite,
what a scanner actually does. The ``ModuleRegistry`` is what the Phase-3 Planner
queries to know which modules exist and what each is good for.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator, Optional


class ModuleCategory(str, Enum):
    RECON = "recon"
    SCANNER = "scanner"
    VALIDATOR = "validator"
    REPORTER = "reporter"
    EXPORT = "export"


@dataclass(frozen=True)
class ModuleMetadata:
    """Static description of a module — the part the Planner reads to select tools."""
    name: str                       # stable id, must be unique in the registry
    version: str
    category: ModuleCategory
    display_name: str
    description: str
    tools_used: list[str] = field(default_factory=list)   # e.g. ["nuclei", "katana"]
    tags: list[str] = field(default_factory=list)
    # Technology signals this module is especially valuable against, so the
    # Planner can be technology-aware (e.g. {"wordpress", "graphql"}).
    tech_affinity: list[str] = field(default_factory=list)
    # Whether running this module reaches out over the network to the target.
    requires_network: bool = True


@dataclass
class ConfigValidation:
    """Result of validating a module's configuration before execution."""
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    normalized_config: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionContext:
    """Everything a module needs to run one job, carried uniformly.

    ``cancel_token`` and ``pause_event`` are cooperative: a module's execute()
    is expected to check them between tool stages (never mid-syscall), so the
    lifecycle can pause/resume/cancel without killing work uncleanly.
    """
    program_id: str
    workspace_id: Optional[str]
    user_id: str
    config: dict[str, Any] = field(default_factory=dict)
    scope: list[str] = field(default_factory=list)          # in-scope asset values
    out_of_scope: list[str] = field(default_factory=list)
    cancel_token: "CancelToken" = field(default_factory=lambda: CancelToken())
    pause_event: "PauseEvent" = field(default_factory=lambda: PauseEvent())


class CancelToken:
    """A one-shot cooperative cancellation flag."""
    def __init__(self) -> None:
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    @property
    def cancelled(self) -> bool:
        return self._cancelled


class PauseEvent:
    """A cooperative pause flag a module checks between stages."""
    def __init__(self) -> None:
        self._paused = False

    def pause(self) -> None:
        self._paused = True

    def resume(self) -> None:
        self._paused = False

    @property
    def paused(self) -> bool:
        return self._paused


class ModuleEventType(str, Enum):
    LOG = "log"
    PROGRESS = "progress"
    PARTIAL_RESULT = "partial_result"
    STAGE_START = "stage_start"
    STAGE_END = "stage_end"


@dataclass
class ModuleEvent:
    """A single streamed event from a running module."""
    type: ModuleEventType
    message: str = ""
    progress: Optional[float] = None            # 0.0 – 1.0
    data: dict[str, Any] = field(default_factory=dict)
    level: str = "info"                          # info | warning | error | success


@dataclass
class GraphNode:
    label: str                                   # Neo4j label, e.g. "Endpoint"
    key: str                                      # natural key for merge
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    type: str                                     # relationship type
    from_key: str
    to_key: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedResult:
    """A module's raw output mapped into graph-ready nodes/edges + findings."""
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""


@dataclass
class ValidationSignals:
    """Confidence / false-positive signals attached to a result. This is the raw
    material the Phase-3 AI Validation wrapper turns into a ValidatedFinding."""
    confidence: float = 0.0                       # 0–100
    false_positive_indicators: list[str] = field(default_factory=list)
    supporting_evidence: list[str] = field(default_factory=list)
    suggested_next_steps: list[str] = field(default_factory=list)


class ModuleContract(ABC):
    """The interface every module implements (via a thin adapter)."""

    @abstractmethod
    def metadata(self) -> ModuleMetadata:
        ...

    @abstractmethod
    def validate_config(self, cfg: dict[str, Any]) -> ConfigValidation:
        ...

    @abstractmethod
    async def execute(self, ctx: ExecutionContext) -> AsyncIterator[ModuleEvent]:
        ...

    @abstractmethod
    def normalize_result(self, raw: Any) -> NormalizedResult:
        ...

    @abstractmethod
    def validation_signals(self, result: NormalizedResult) -> ValidationSignals:
        ...
