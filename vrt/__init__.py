"""Bugcrowd VRT taxonomy + honest platform coverage map + OWASP Top 10 map."""
from .coverage import Coverage, classify, coverage_report, entries_for_method
from .owasp import ALL as owasp_all
from .owasp import API_2023, LLM_2025, MOBILE_2024, WEB_2021, OwaspCategory
from .owasp import report as owasp_report
from .taxonomy import VrtEntry, categories, load, lookup, severity_rank

__all__ = [
    "VrtEntry", "load", "lookup", "categories", "severity_rank",
    "Coverage", "classify", "coverage_report", "entries_for_method",
    "OwaspCategory", "WEB_2021", "API_2023", "MOBILE_2024", "LLM_2025",
    "owasp_all", "owasp_report",
]
