"""Scan a GitHub repository (URL or owner/name) for vulnerabilities.

Clones the repo once, then runs the platform's existing static detectors over
the whole tree — IaC/DevOps misconfiguration (iac_scan) and value-pattern secret
detection (the js_recon SECRET_PATTERNS) — and aggregates the findings with
severity + a summary. Composes existing modules; it does not reimplement them.
"""
from .repo_scanner import scan_repo, scan_tree, RepoScanResult

__all__ = ["scan_repo", "scan_tree", "RepoScanResult"]
