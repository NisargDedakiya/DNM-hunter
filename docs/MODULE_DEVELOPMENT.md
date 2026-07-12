# Module & Plugin Development Guide

How to add a new scanning/recon capability to NisargHunter AI as an installable
module — one that the Planner can select, the lifecycle can queue/pause/cancel,
and the Marketplace can show with its permissions.

There are two pieces, and every module needs both:

1. A **`ModuleContract`** implementation (Python) — the runtime interface.
2. A **`plugin.manifest.json`** (validated) — the installable-module descriptor.

---

## 1. Implement the `ModuleContract`

The contract lives in [`common/module_contract.py`](../common/module_contract.py)
and defines the uniform lifecycle every module speaks:

```
Metadata -> Configuration -> Execution -> Result -> Validation -> Report -> Logs
```

Subclass `ModuleContract` (or, for a scanner that already has a `main.py`, wrap
it with a thin adapter like the ones in
[`common/adapters/builtin_adapters.py`](../common/adapters/builtin_adapters.py) —
**wrap, don't rewrite** the scanning logic):

```python
from common.module_contract import (
    ModuleContract, ModuleMetadata, ModuleCategory, ConfigValidation,
    ExecutionContext, ModuleEvent, ModuleEventType, NormalizedResult, ValidationSignals,
)

class MyScannerAdapter(ModuleContract):
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="my_scanner", version="1.0", category=ModuleCategory.SCANNER,
            display_name="My Scanner", description="...",
            tools_used=["mytool"], tech_affinity=["graphql"],  # Planner uses this
        )

    def validate_config(self, cfg) -> ConfigValidation: ...
    async def execute(self, ctx: ExecutionContext):        # cooperative pause/cancel
        if ctx.cancel_token.cancelled: return
        yield ModuleEvent(type=ModuleEventType.STAGE_START, message="starting")
        # delegate to your existing scanner here
    def normalize_result(self, raw) -> NormalizedResult: ...   # graph-ready nodes/edges
    def validation_signals(self, result) -> ValidationSignals: ...  # confidence + FP
```

Register it so the Planner can see it:

```python
from common.module_registry import default_registry
default_registry.register(MyScannerAdapter())
```

### Why `tech_affinity` matters

The [recon planner](../common/recon_planner.py) reads `tech_affinity` to build
**technology-aware** plans: if the target is detected as GraphQL, modules with
`graphql` affinity are prioritized `high`. Declare the technologies your module
is genuinely good against — that is what makes the plan feel intelligent.

### Lifecycle

Jobs move through [`common/job_lifecycle.py`](../common/job_lifecycle.py):

```
QUEUED -> RUNNING -> (PAUSED <-> RUNNING) -> COMPLETED | CANCELLED | FAILED
FAILED -> RETRYING -> RUNNING
```

Your `execute()` must check `ctx.pause_event` and `ctx.cancel_token` **between
tool stages** (never mid-syscall) so pause/resume/cancel work cleanly. You do
**not** manage the queue or concurrency — the orchestrator does, deferring
capacity to the `resource_governor`. Never bypass it.

---

## 2. Ship a `plugin.manifest.json`

The manifest schema is defined and validated in
[`webapp/src/lib/pluginManifest.ts`](../webapp/src/lib/pluginManifest.ts). It is a
**superset** of the legacy catalog shape, so existing `plugins/*/*.json` keep
working; new fields are optional. Place your manifest under
`plugins/<category>/<id>.json`.

```jsonc
{
  "id": "my_scanner",
  "name": "My Scanner",
  "category": "scanner",              // recon | scanner | validator | reporter | export
  "kind": "mcp-server",               // mcp-server | builtin | webapp-subsystem
  "description": "What it does.",
  "dockerService": "kali-sandbox",
  "mcpPort": 8010,
  "status": "community",
  "tags": ["graphql"],

  // ── installable-module fields (Phase 6) ──
  "version": "1.0.0",
  "author": "you",
  "moduleContractEntrypoint": "common.adapters.my_scanner:MyScannerAdapter",
  "requiredTools": ["mytool"],
  "configSchema": { "type": "object", "properties": { "depth": { "type": "integer" } } },
  "permissions": [
    { "scope": "network:target", "reason": "Sends requests to in-scope hosts." },
    { "scope": "scope:in-scope-only", "reason": "RoE guardrail blocks out-of-scope targets." }
  ],
  "compatibility": { "minPlatformVersion": "2.0.0" }
}
```

### Permissions are not optional

A plugin executes security tools, so it **must** declare what it touches. The
Marketplace shows `permissions` before a plugin is enabled, and the loader
enforces them against the existing RoE `hard_guardrail` — a manifest can never
widen what a plugin is allowed to reach. Declare `network:*` and `scope:*`
honestly.

See [`plugins/scanner/nuclei.json`](../plugins/scanner/nuclei.json) and
[`plugins/recon/katana.json`](../plugins/recon/katana.json) as complete
reference plugins implementing both the manifest and the `ModuleContract`.

---

## Checklist

- [ ] `ModuleContract` implemented (or a thin adapter wrapping existing `main.py`)
- [ ] Registered into `default_registry`
- [ ] `tech_affinity` declared for technology-aware planning
- [ ] `execute()` checks `pause_event` / `cancel_token` between stages
- [ ] `plugin.manifest.json` validates (`validateManifest`)
- [ ] `permissions` declared honestly (`network:*`, `scope:*`)
- [ ] Unit tests for the adapter + a manifest fixture
