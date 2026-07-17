"""NisargHunter AI unified scanner suite — one orchestrator over the whole
static analysis stack, with VRT-tagged findings and SARIF 2.1.0 export.
"""
from .orchestrator import SuiteFinding, SuiteResult, scan, scan_many
from .sarif import to_sarif, to_sarif_json

__all__ = ["SuiteFinding", "SuiteResult", "scan", "scan_many", "to_sarif", "to_sarif_json"]
