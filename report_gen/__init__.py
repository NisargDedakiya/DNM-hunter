"""Professional report generation — enrich scanner findings with CVSS, VRT/CWE,
verification steps, remediation, and references; render Markdown or HTML.
"""
from .knowledge import Guidance, guidance_for
from .report import EnrichedFinding, Report, build_report, enrich, to_html, to_markdown

__all__ = [
    "Guidance", "guidance_for",
    "EnrichedFinding", "Report", "build_report", "enrich", "to_markdown", "to_html",
]
