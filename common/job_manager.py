"""In-process job queue + admission (master-plan Phase 2, Priority 7).

Holds the set of lifecycle Jobs and decides, purely, which QUEUED jobs may
start given a concurrency cap. It does NOT run containers and does NOT know the
memory governor — the orchestrator passes an ``admit`` predicate so the real
``resource_governor`` stays the single source of truth for capacity. This keeps
the queue logic testable and incapable of bypassing the governor.
"""

from __future__ import annotations

from typing import Callable, Optional

from .job_lifecycle import Job, JobState


class JobManager:
    def __init__(self, max_concurrent: int = 2) -> None:
        if max_concurrent < 1:
            raise ValueError("max_concurrent must be >= 1")
        self.max_concurrent = max_concurrent
        self._jobs: dict[str, Job] = {}

    def submit(self, job: Job) -> Job:
        if job.id in self._jobs:
            raise ValueError(f"job {job.id} already submitted")
        self._jobs[job.id] = job
        return job

    def get(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)

    def all(self) -> list[Job]:
        return list(self._jobs.values())

    @property
    def running_count(self) -> int:
        return sum(1 for j in self._jobs.values() if j.state is JobState.RUNNING)

    def queued(self) -> list[Job]:
        return [j for j in self._jobs.values() if j.state is JobState.QUEUED]

    def position_of(self, job_id: str) -> Optional[int]:
        """1-indexed position of a job in the QUEUED line, or None if not queued."""
        q = self.queued()
        for i, j in enumerate(q):
            if j.id == job_id:
                return i + 1
        return None

    def next_startable(self, admit: Optional[Callable[[Job], bool]] = None) -> list[Job]:
        """Which QUEUED (or RETRYING) jobs may start now, respecting the
        concurrency cap AND an optional external ``admit`` predicate (the
        resource governor). Returns them in queue order, never exceeding the
        remaining slots."""
        slots = self.max_concurrent - self.running_count
        if slots <= 0:
            return []
        candidates = [
            j for j in self._jobs.values()
            if j.state in (JobState.QUEUED, JobState.RETRYING)
        ]
        startable: list[Job] = []
        for j in candidates:
            if len(startable) >= slots:
                break
            if admit is None or admit(j):
                startable.append(j)
        return startable

    def prune_terminal(self) -> int:
        """Drop COMPLETED/CANCELLED jobs; returns how many were removed."""
        terminal = [jid for jid, j in self._jobs.items() if j.is_terminal]
        for jid in terminal:
            del self._jobs[jid]
        return len(terminal)
