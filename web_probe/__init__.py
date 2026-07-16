"""Dynamic live-HTTP security scanner — VRT-mapped detection of the
Server Security Misconfiguration / transport / CORS / clickjacking rows that
are only observable against a running target.
"""
from .scanner import WebFinding, analyze_response, probe_url

__all__ = ["WebFinding", "analyze_response", "probe_url"]
