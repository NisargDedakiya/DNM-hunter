"""OWASP LLM Top 10 (2025) static detection for LLM-application source code.

Scans Python / JS / TS source for the anti-patterns behind the OWASP Top 10 for
LLM applications — prompt injection surfaces, unsafe model output handling,
untrusted model/data loading, system-prompt secret leakage, unbounded
consumption, and over-autonomous agents — mapping each finding to its LLMxx id.
"""
from .scanner import scan_llm_code, scan_tree, LlmFinding, LLM_TOP10

__all__ = ["scan_llm_code", "scan_tree", "LlmFinding", "LLM_TOP10"]
