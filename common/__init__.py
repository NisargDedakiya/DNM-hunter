"""Shared cross-service contracts for NisargHunter AI (master-plan Phase 2).

This package defines the uniform interface every scanning/recon module speaks —
Metadata -> Configuration -> Execution -> Result -> Validation -> Report -> Logs —
plus the job-lifecycle state machine (queue/pause/resume/cancel/retry) that the
orchestrator uses to treat all modules identically. It deliberately holds no
scanning logic of its own; adapters wrap the existing modules.
"""
