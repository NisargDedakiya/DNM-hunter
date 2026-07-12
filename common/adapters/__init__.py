"""Thin adapters that wrap each existing module in the ModuleContract
(master-plan Phase 2, Priority 6).

Importing this package registers every built-in module into the
``default_registry`` so the Planner sees a complete, deterministic module set.
The adapters wrap — they never reimplement — what a scanner does: metadata,
config validation, result normalization, and validation signals live here;
``execute()`` delegates to the module's existing orchestrator entrypoint.
"""

from .builtin_adapters import register_builtin_modules

__all__ = ["register_builtin_modules"]
