"""SARIF 2.1.0 export for suite results.

SARIF (Static Analysis Results Interchange Format, OASIS standard) is the
interchange format consumed by GitHub code scanning, Azure DevOps, VS Code, and
most security dashboards. Emitting it makes the suite a drop-in citizen of a
standard CI security pipeline (upload via github/codeql-action/upload-sarif).

We build a minimal-but-valid 2.1.0 document: one run, one tool driver whose
`rules[]` are the distinct rule ids seen, and one `results[]` entry per finding
with a ruleId, level, message, and physical location.
"""

from __future__ import annotations

import json

# VRT/severity → SARIF result level. SARIF has no "critical"; error covers it.
_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
          "low": "note", "info": "note"}

# SARIF security-severity is a 0.0–10.0 string GitHub uses to rank alerts.
_SEC_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.0",
                 "low": "3.0", "info": "1.0"}

SARIF_VERSION = "2.1.0"
_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def to_sarif(result, tool_name: str = "NisargHunter AI", tool_version: str = "1.0.0") -> dict:
    """Convert a scanner_suite.SuiteResult into a SARIF 2.1.0 document (dict)."""
    # distinct rules, preserving first-seen title/help for the driver.rules table
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in result.findings:
        rid = f.rule_id or "GENERIC"
        if rid not in rules:
            rule = {
                "id": rid,
                "name": rid.replace("-", "").replace("_", ""),
                "shortDescription": {"text": f.title[:120] or rid},
                "fullDescription": {"text": f.detail or f.title or rid},
                "defaultConfiguration": {"level": _LEVEL.get(f.severity, "warning")},
                "properties": {
                    "security-severity": _SEC_SEVERITY.get(f.severity, "5.0"),
                    "tags": ["security"] + ([f.category] if f.category else []),
                },
            }
            if f.vrt:
                rule["properties"]["vrt"] = f.vrt
            rules[rid] = rule

        res = {
            "ruleId": rid,
            "level": _LEVEL.get(f.severity, "warning"),
            "message": {"text": f.detail or f.title},
            "properties": {"scanner": f.scanner, "severity": f.severity},
        }
        if f.vrt:
            res["properties"]["vrt"] = f.vrt
        conf = getattr(f, "confidence", "")
        if conf:
            res["properties"]["confidence"] = conf
        if f.file:
            region = {}
            if f.line is not None and f.line > 0:
                region["startLine"] = f.line
            res["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    **({"region": region} if region else {}),
                }
            }]
        results.append(res)

    return {
        "version": SARIF_VERSION,
        "$schema": _SCHEMA,
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": "https://github.com/NisargDedakiya/DNM-hunter",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "properties": {
                "target": result.target,
                "summary": result.summary,
                **({"errors": result.errors} if result.errors else {}),
            },
        }],
    }


def to_sarif_json(result, **kw) -> str:
    return json.dumps(to_sarif(result, **kw), indent=2)
