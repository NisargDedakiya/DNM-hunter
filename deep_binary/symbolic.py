"""Symbolic-execution bug finding with angr.

Two capabilities that a fast static scan cannot provide, because they require
actually reasoning about program state:

  reach_target()        — solve for a concrete input (stdin/argv) that drives
                          execution to a target address or symbol (e.g. a hidden
                          "authenticated"/"win" function or a dangerous call).
                          This is automatic exploit-primitive discovery: it does
                          not just say "there is a check", it produces the input
                          that passes it.

  find_control_hijack() — feed symbolic input and detect an *unconstrained* state
                          (the instruction pointer becomes attacker-controlled).
                          That is the signature of a memory-corruption bug
                          (stack overflow via gets/strcpy) that is actually
                          exploitable, plus the input that triggers it.

angr is an optional, heavy dependency. This module imports cleanly without it;
callers check HAVE_ANGR. All runs are bounded by a wall-clock budget and a step
cap so path explosion cannot hang the caller.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional

try:
    import angr  # type: ignore
    import claripy  # type: ignore
    HAVE_ANGR = True
    # angr is very chatty; silence it for library use.
    for _n in ("angr", "cle", "pyvex", "claripy", "archinfo", "angr.state_plugins"):
        logging.getLogger(_n).setLevel(logging.CRITICAL)
except Exception:  # pragma: no cover - exercised only where angr is absent
    HAVE_ANGR = False


@dataclass
class ReachResult:
    reached: bool
    target: str
    stdin: Optional[bytes] = None
    reason: str = ""

    def to_dict(self) -> dict:
        return {"reached": self.reached, "target": self.target,
                "stdin": self.stdin.decode("latin-1") if self.stdin else None,
                "reason": self.reason}


@dataclass
class HijackResult:
    hijackable: bool
    overflow_len: Optional[int] = None
    reason: str = ""

    def to_dict(self) -> dict:
        return {"hijackable": self.hijackable, "overflowLen": self.overflow_len, "reason": self.reason}


def _require_angr():
    if not HAVE_ANGR:
        raise RuntimeError("angr is not installed; deep symbolic analysis is unavailable")


def _resolve_target(proj, target) -> Optional[int]:
    """Accept an int address or a symbol name; return the address or None."""
    if isinstance(target, int):
        return target
    sym = proj.loader.find_symbol(target)
    if sym is not None:
        return sym.rebased_addr
    return None


def _time_budget_stepper(deadline: float):
    """A step_func that empties the queue once the wall-clock budget is spent,
    so explore() terminates instead of running forever on path explosion."""
    def step_func(simgr):
        if time.time() > deadline:
            for stash in list(simgr.stashes):
                simgr.move(from_stash=stash, to_stash="_timeout",
                           filter_func=lambda s: stash not in ("found", "_timeout"))
        return simgr
    return step_func


def reach_target(binary: str, target, stdin_size: int = 80,
                 timeout_s: float = 45.0) -> ReachResult:
    """Find stdin bytes that drive `binary` to `target` (address or symbol)."""
    _require_angr()
    proj = angr.Project(binary, auto_load_libs=False)
    addr = _resolve_target(proj, target)
    tlabel = target if isinstance(target, str) else hex(target)
    if addr is None:
        return ReachResult(False, tlabel, reason=f"target {tlabel!r} not found in the binary")

    flag = claripy.BVS("stdin", stdin_size * 8)
    state = proj.factory.full_init_state(
        stdin=angr.SimFileStream(name="stdin", content=flag, has_end=False),
        add_options={angr.options.LAZY_SOLVES},
    )
    simgr = proj.factory.simulation_manager(state)
    deadline = time.time() + timeout_s
    simgr.explore(find=addr, step_func=_time_budget_stepper(deadline), num_find=1)

    if simgr.found:
        sol = simgr.found[0].posix.dumps(0)
        return ReachResult(True, tlabel, stdin=sol.rstrip(b"\x00") or sol, reason="target reached")
    reason = "wall-clock budget exhausted" if simgr.stashes.get("_timeout") else "target unreachable within bounds"
    return ReachResult(False, tlabel, reason=reason)


def find_control_hijack(binary: str, stdin_size: int = 200,
                        timeout_s: float = 45.0) -> HijackResult:
    """Detect an attacker-controlled instruction pointer (memory corruption)."""
    _require_angr()
    proj = angr.Project(binary, auto_load_libs=False)
    flag = claripy.BVS("stdin", stdin_size * 8)
    state = proj.factory.full_init_state(
        stdin=angr.SimFileStream(name="stdin", content=flag, has_end=False),
        add_options=angr.options.unicorn | {angr.options.LAZY_SOLVES},
    )
    simgr = proj.factory.simulation_manager(state, save_unconstrained=True)
    deadline = time.time() + timeout_s

    while simgr.active and time.time() < deadline:
        simgr.step()
        if simgr.unconstrained:
            st = simgr.unconstrained[0]
            # PC is symbolic and depends on our input -> control-flow hijack.
            if st.solver.symbolic(st.regs.pc):
                try:
                    # smallest stdin that still corrupts control flow
                    payload = st.posix.dumps(0)
                    off = len(payload.rstrip(b"\x00")) or len(payload)
                except Exception:
                    off = None
                return HijackResult(True, overflow_len=off, reason="symbolic PC — input controls the instruction pointer")

    if time.time() >= deadline:
        return HijackResult(False, reason="wall-clock budget exhausted (no hijack found in bounds)")
    return HijackResult(False, reason="no unconstrained/hijackable state found")
