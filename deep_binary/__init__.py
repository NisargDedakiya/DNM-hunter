"""Deep binary analysis via symbolic execution (angr).

The heavy tier below the fast checksec-style binary_audit: symbolically explores
a compiled binary to (1) solve for an input that reaches a target/dangerous
state, and (2) detect memory-corruption bugs where attacker input can hijack the
instruction pointer (unconstrained PC). angr is an optional dependency — the
module imports without it and reports availability via HAVE_ANGR.
"""
from .symbolic import (
    HAVE_ANGR,
    HijackResult,
    ReachResult,
    find_control_hijack,
    reach_target,
)

__all__ = ["HAVE_ANGR", "reach_target", "find_control_hijack", "ReachResult", "HijackResult"]
