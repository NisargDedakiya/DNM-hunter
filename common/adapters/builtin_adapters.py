"""Adapters for the built-in scanning/recon modules (master-plan Phase 2).

Each adapter implements ``ModuleContract`` by describing a real module dir
(recon/, gvm_scan/, github_secret_hunt/, trufflehog_scan/, iac_scan/,
cloud_recon/, ai_attack_surface_scan/) and delegating execution to the existing
recon_orchestrator start flow — the actual scanning code is untouched.

The concrete ``execute()`` here yields a single terminal event describing the
delegation target rather than reimplementing the scan; the orchestrator remains
responsible for the container lifecycle (and thus the resource_governor and
hard_guardrail it already enforces). This satisfies the contract uniformly
without rewriting what any scanner does.
"""

from __future__ import annotations

from typing import Any, AsyncIterator

from ..module_contract import (
    ConfigValidation, ExecutionContext, ModuleCategory, ModuleContract,
    ModuleEvent, ModuleEventType, ModuleMetadata, NormalizedResult, ValidationSignals,
)
from ..module_registry import ModuleRegistry, default_registry


class _BaseModuleAdapter(ModuleContract):
    """Shared adapter behavior; subclasses provide metadata + orchestrator route."""

    #: the recon_orchestrator start endpoint this module delegates execution to
    orchestrator_route: str = ""

    _META: ModuleMetadata

    def metadata(self) -> ModuleMetadata:
        return self._META

    def validate_config(self, cfg: dict[str, Any]) -> ConfigValidation:
        # Every module needs a program to run against; network modules also need
        # at least one in-scope asset. Kept intentionally generic — module-
        # specific schema validation belongs to the plugin manifest (Phase 6).
        errors: list[str] = []
        if not cfg.get("program_id"):
            errors.append("program_id is required")
        if self._META.requires_network and not cfg.get("scope"):
            errors.append("at least one in-scope asset is required for a network module")
        return ConfigValidation(ok=not errors, errors=errors, normalized_config=dict(cfg))

    async def execute(self, ctx: ExecutionContext) -> AsyncIterator[ModuleEvent]:
        # Cooperative cancel/pause checks happen here in the uniform layer; the
        # actual scan is launched by the orchestrator via orchestrator_route.
        if ctx.cancel_token.cancelled:
            yield ModuleEvent(type=ModuleEventType.STAGE_END, message="cancelled before start", level="warning")
            return
        yield ModuleEvent(
            type=ModuleEventType.STAGE_START,
            message=f"{self._META.display_name}: delegating to orchestrator {self.orchestrator_route}",
            data={"route": self.orchestrator_route, "program_id": ctx.program_id},
        )

    def normalize_result(self, raw: Any) -> NormalizedResult:
        # Modules that produce graph data already write it via their own
        # normalizers; the uniform shape here carries a summary + passthrough
        # findings so the orchestrator can treat every result identically.
        if isinstance(raw, NormalizedResult):
            return raw
        findings = raw.get("findings", []) if isinstance(raw, dict) else []
        summary = raw.get("summary", "") if isinstance(raw, dict) else ""
        return NormalizedResult(findings=list(findings), summary=str(summary))

    def validation_signals(self, result: NormalizedResult) -> ValidationSignals:
        # A neutral baseline; the Phase-3 AI validator refines these per finding.
        n = len(result.findings)
        return ValidationSignals(
            confidence=0.0 if n == 0 else 50.0,
            supporting_evidence=[result.summary] if result.summary else [],
        )


class ReconAdapter(_BaseModuleAdapter):
    orchestrator_route = "/recon/start"
    _META = ModuleMetadata(
        name="recon", version="1.0", category=ModuleCategory.RECON,
        display_name="Attack-Surface Recon",
        description="Subdomain discovery, port scan, HTTP probe, JS/param attack-surface enumeration and CVE enrichment.",
        tools_used=["katana", "gau", "jsluice", "paramspider", "arjun", "ffuf", "kiterunner", "naabu", "nuclei"],
        tags=["recon", "attack-surface", "js", "params"],
        tech_affinity=["spa", "graphql", "rest", "wordpress"],
    )


class GvmScanAdapter(_BaseModuleAdapter):
    orchestrator_route = "/gvm/start"
    _META = ModuleMetadata(
        name="gvm_scan", version="1.0", category=ModuleCategory.SCANNER,
        display_name="GVM Vulnerability Scan",
        description="Greenbone/OpenVAS authenticated + unauthenticated network vulnerability scanning.",
        tools_used=["gvm", "openvas"], tags=["network", "cve", "authenticated"],
        tech_affinity=["network", "infrastructure"],
    )


class GithubSecretHuntAdapter(_BaseModuleAdapter):
    orchestrator_route = "/github-hunt/start"
    _META = ModuleMetadata(
        name="github_secret_hunt", version="1.0", category=ModuleCategory.SCANNER,
        display_name="GitHub Secret Hunt",
        description="Enumerates a target's public GitHub org/repos for leaked secrets and sensitive artifacts.",
        tools_used=["github-api", "gitleaks"], tags=["secrets", "osint", "github"],
        tech_affinity=["github"], requires_network=True,
    )


class TrufflehogScanAdapter(_BaseModuleAdapter):
    orchestrator_route = "/trufflehog/start"
    _META = ModuleMetadata(
        name="trufflehog_scan", version="1.0", category=ModuleCategory.SCANNER,
        display_name="TruffleHog Secret Scan",
        description="Deep secret scanning of repositories and filesystems with verified-credential detection.",
        tools_used=["trufflehog"], tags=["secrets", "verified"],
        tech_affinity=["github", "filesystem"],
    )


class IacScanAdapter(_BaseModuleAdapter):
    orchestrator_route = "/iac/start"
    _META = ModuleMetadata(
        name="iac_scan", version="1.0", category=ModuleCategory.SCANNER,
        display_name="IaC / DevOps Misconfig Scan",
        description="Static misconfiguration scanning of Dockerfiles, Kubernetes manifests, GitHub Actions and Terraform.",
        tools_used=["checkov", "trivy"], tags=["iac", "devops", "misconfig"],
        tech_affinity=["docker", "kubernetes", "terraform", "github-actions"],
        requires_network=False,
    )


class CloudReconAdapter(_BaseModuleAdapter):
    orchestrator_route = "/cloud-recon/start"
    _META = ModuleMetadata(
        name="cloud_recon", version="1.0", category=ModuleCategory.RECON,
        display_name="Cloud Storage Recon",
        description="Enumerates cloud storage buckets (S3/GCS/Azure) and checks for public exposure.",
        tools_used=["cloud_enum"], tags=["cloud", "buckets", "exposure"],
        tech_affinity=["aws", "gcp", "azure"],
    )


class AiAttackSurfaceAdapter(_BaseModuleAdapter):
    orchestrator_route = "/ai-attack-surface/start"
    _META = ModuleMetadata(
        name="ai_attack_surface_scan", version="1.0", category=ModuleCategory.SCANNER,
        display_name="AI Attack-Surface (Gauntlet)",
        description="Agent-driven attack-surface exploration that chains tools against enumerated endpoints.",
        tools_used=["agent", "mcp-tools"], tags=["ai", "attack-chain", "agent"],
        tech_affinity=["rest", "graphql", "spa"],
    )


_ALL_ADAPTERS: list[type[_BaseModuleAdapter]] = [
    ReconAdapter, GvmScanAdapter, GithubSecretHuntAdapter, TrufflehogScanAdapter,
    IacScanAdapter, CloudReconAdapter, AiAttackSurfaceAdapter,
]


def register_builtin_modules(registry: ModuleRegistry = default_registry) -> ModuleRegistry:
    """Register every built-in adapter. Idempotent: modules already present are
    left as-is, so calling this from multiple entrypoints is safe."""
    existing = {m.name for m in registry.metadata()}
    for adapter_cls in _ALL_ADAPTERS:
        adapter = adapter_cls()
        if adapter.metadata().name not in existing:
            registry.register(adapter)
    return registry
