"""Scan-lifecycle state machine (master-plan Phase 2, Priority 7).

Every module job moves through one explicit state machine so queue / pause /
resume / restart / cancel / retry behave identically no matter which scanner is
running:

    QUEUED -> RUNNING -> (PAUSED <-> RUNNING) -> COMPLETED | CANCELLED | FAILED
    FAILED -> RETRYING -> RUNNING

This module is pure state logic — it holds no containers, sockets, or timers, so
it is fully unit-testable and cannot, by construction, bypass the
resource_governor or hard_guardrail. The orchestrator owns the side effects
(pulling from the queue, tearing down containers) and drives transitions here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class JobState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    RETRYING = "retrying"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


# Allowed transitions. Anything not listed here is rejected — a job can never
# jump from, say, COMPLETED back to RUNNING without going through retry.
_TRANSITIONS: dict[JobState, set[JobState]] = {
    JobState.QUEUED: {JobState.RUNNING, JobState.CANCELLED},
    JobState.RUNNING: {JobState.PAUSED, JobState.COMPLETED, JobState.CANCELLED, JobState.FAILED},
    JobState.PAUSED: {JobState.RUNNING, JobState.CANCELLED, JobState.FAILED},
    JobState.RETRYING: {JobState.RUNNING, JobState.CANCELLED},
    JobState.FAILED: {JobState.RETRYING},
    # Terminal states below reject all transitions.
    JobState.COMPLETED: set(),
    JobState.CANCELLED: set(),
}

TERMINAL_STATES = {JobState.COMPLETED, JobState.CANCELLED}


class InvalidTransition(Exception):
    """Raised when a state transition is not permitted by the machine."""


def can_transition(src: JobState, dst: JobState) -> bool:
    return dst in _TRANSITIONS.get(src, set())


@dataclass
class Job:
    """A single unit of scanning work tracked through the lifecycle."""
    id: str
    module_name: str
    program_id: str
    config: dict = field(default_factory=dict)
    state: JobState = JobState.QUEUED
    progress: float = 0.0
    error: Optional[str] = None
    retries: int = 0
    max_retries: int = 3

    def _to(self, dst: JobState) -> None:
        if not can_transition(self.state, dst):
            raise InvalidTransition(f"{self.module_name} job {self.id}: {self.state.value} -> {dst.value} not allowed")
        self.state = dst

    # ── Lifecycle operations ──
    def start(self) -> None:
        """QUEUED/RETRYING -> RUNNING."""
        self._to(JobState.RUNNING)

    def pause(self) -> None:
        self._to(JobState.PAUSED)

    def resume(self) -> None:
        if self.state is not JobState.PAUSED:
            raise InvalidTransition(f"job {self.id} is not paused")
        self._to(JobState.RUNNING)

    def complete(self) -> None:
        self._to(JobState.COMPLETED)
        self.progress = 1.0

    def cancel(self) -> None:
        self._to(JobState.CANCELLED)

    def fail(self, error: str) -> None:
        self._to(JobState.FAILED)
        self.error = error

    def retry(self) -> None:
        """FAILED -> RETRYING, preserving the original config. Refuses once the
        retry budget is exhausted so a permanently-broken job can't loop forever."""
        if self.state is not JobState.FAILED:
            raise InvalidTransition(f"job {self.id} can only be retried from FAILED")
        if self.retries >= self.max_retries:
            raise InvalidTransition(f"job {self.id} exhausted its {self.max_retries} retries")
        self.retries += 1
        self.error = None
        self._to(JobState.RETRYING)

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    @property
    def is_active(self) -> bool:
        return self.state in {JobState.RUNNING, JobState.PAUSED, JobState.RETRYING}
