"""Deterministic CVSS v3.1 base-score calculator.

Encodes the official FIRST.org CVSS v3.1 specification directly, so a base
score is computed *by construction* from a vector string — never guessed by a
model and never dependent on an NVD lookup. This fills the real gap in
recon/helpers/cve_helpers.py, which can only read a precomputed NVD score: a
novel finding the agent identifies (with a vector but no CVE) can now be scored.

Reference: https://www.first.org/cvss/v3.1/specification-document (section 7).
Validated against published vectors (e.g. Log4Shell CVE-2021-44228 -> 10.0).
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# --- Metric value tables (CVSS v3.1 spec, section 7.4) ---
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
# Privileges Required is scope-dependent.
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

_REQUIRED = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}


class InvalidVector(ValueError):
    """Raised when a CVSS vector string is malformed or missing metrics."""


@dataclass(frozen=True)
class CvssResult:
    base_score: float
    severity: str          # None | Low | Medium | High | Critical
    vector: str
    metrics: dict


def parse_vector(vector: str) -> dict:
    """Parse a 'CVSS:3.1/AV:N/AC:L/...' (or bare 'AV:N/AC:L/...') string into a
    {metric: value} dict. Raises InvalidVector on malformed input."""
    if not vector or not isinstance(vector, str):
        raise InvalidVector("empty vector")
    parts = [p for p in vector.strip().split("/") if p]
    metrics: dict[str, str] = {}
    for p in parts:
        if ":" not in p:
            raise InvalidVector(f"malformed component: {p!r}")
        k, v = p.split(":", 1)
        k = k.strip().upper()
        v = v.strip().upper()
        if k in ("CVSS",):  # version prefix, ignore
            continue
        metrics[k] = v
    missing = _REQUIRED - metrics.keys()
    if missing:
        raise InvalidVector(f"missing base metrics: {', '.join(sorted(missing))}")
    return metrics


def _roundup(value: float) -> float:
    """CVSS 3.1 Roundup: smallest number to 1 decimal place that is >= value.
    Uses the spec's integer method to dodge float representation errors."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def severity_rating(score: float) -> str:
    """CVSS v3.1 qualitative severity band."""
    if score <= 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def base_score(vector: str) -> CvssResult:
    """Compute the CVSS v3.1 base score from a vector string."""
    m = parse_vector(vector)
    try:
        scope_changed = m["S"] == "C"
        av = _AV[m["AV"]]
        ac = _AC[m["AC"]]
        ui = _UI[m["UI"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[m["PR"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError as exc:
        raise InvalidVector(f"invalid metric value: {exc}") from exc

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = _roundup(min(1.08 * (impact + exploitability), 10))
    else:
        score = _roundup(min(impact + exploitability, 10))

    return CvssResult(base_score=score, severity=severity_rating(score), vector=vector, metrics=m)
