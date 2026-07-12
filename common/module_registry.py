"""The module registry (master-plan Phase 2, Priority 6).

A single place that knows every module implementing ``ModuleContract``. The
Phase-3 Planner queries this to build technology-aware recon plans that only
reference modules that actually exist. Registration is explicit (adapters
register themselves on import) so the set is deterministic and testable.
"""

from __future__ import annotations

from typing import Optional

from .module_contract import ModuleContract, ModuleCategory, ModuleMetadata


class ModuleRegistry:
    """An in-process registry of contract-implementing modules."""

    def __init__(self) -> None:
        self._modules: dict[str, ModuleContract] = {}

    def register(self, module: ModuleContract) -> None:
        name = module.metadata().name
        if name in self._modules:
            raise ValueError(f"Module '{name}' is already registered")
        self._modules[name] = module

    def unregister(self, name: str) -> None:
        self._modules.pop(name, None)

    def get(self, name: str) -> Optional[ModuleContract]:
        return self._modules.get(name)

    def all(self) -> list[ModuleContract]:
        return list(self._modules.values())

    def metadata(self) -> list[ModuleMetadata]:
        return [m.metadata() for m in self._modules.values()]

    def by_category(self, category: ModuleCategory) -> list[ModuleContract]:
        return [m for m in self._modules.values() if m.metadata().category == category]

    def for_tech(self, tech: str) -> list[ModuleContract]:
        """Modules whose metadata declares affinity for a detected technology.
        Used by the Planner to prioritize (e.g. WordPress -> WP-specific scans)."""
        needle = tech.strip().lower()
        return [
            m for m in self._modules.values()
            if any(needle == t.strip().lower() for t in m.metadata().tech_affinity)
        ]

    def clear(self) -> None:
        self._modules.clear()


# Process-wide default registry. Adapters register into this on import; callers
# that need isolation (tests) can construct their own ModuleRegistry.
default_registry = ModuleRegistry()
