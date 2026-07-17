"""Bugcrowd VRT (Vulnerability Rating Taxonomy) as first-class platform data.

`taxonomy.tsv` is the full VRT (severity, category, name, variant). This module
loads it, assigns each row a stable `vrt_id`, and answers two questions the
platform needs:

  1. What is the canonical severity/category for a finding?  → lookup()
  2. Which VRT rows can this platform actually DETECT, and how?  → coverage()

Detectability is deliberately honest. Each row is classified as:
  static       — findable from source/config/binaries by a shipped detector
  dynamic      — only findable against a live target (runtime scanners/agent)
  manual       — needs a human / physical access / economic-logic review
  out_of_scope — hardware, automotive, RF, algorithmic bias: not automatable here

The `static` mapping is keyed on real detector rule namespaces, so coverage
numbers reflect code that exists, not aspiration.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path

_TSV = Path(__file__).with_name("taxonomy.tsv")


@dataclass(frozen=True)
class VrtEntry:
    vrt_id: str
    severity: str          # P1..P5 or "varies"
    category: str
    name: str
    variant: str

    def to_dict(self) -> dict:
        return asdict(self)


def _slug(*parts: str) -> str:
    s = " ".join(p for p in parts if p).lower()
    s = re.sub(r"[^\w]+", "_", s).strip("_")
    return re.sub(r"_+", "_", s)


@lru_cache(maxsize=1)
def load() -> list[VrtEntry]:
    entries: list[VrtEntry] = []
    seen: set[str] = set()
    for i, raw in enumerate(_TSV.read_text(encoding="utf-8").splitlines()):
        if i == 0 or not raw.strip():
            continue
        cols = raw.split("\t")
        sev = (cols[0] if len(cols) > 0 else "").strip()
        cat = (cols[1] if len(cols) > 1 else "").strip()
        name = (cols[2] if len(cols) > 2 else "").strip()
        var = (cols[3] if len(cols) > 3 else "").strip()
        if not cat:
            continue
        base = _slug(cat, name, var) or _slug(cat, name) or _slug(cat)
        vid = base
        n = 2
        while vid in seen:
            vid = f"{base}_{n}"
            n += 1
        seen.add(vid)
        entries.append(VrtEntry(vid, sev.lower() if sev.startswith("P") else "varies",
                                cat, name, var))
    return entries


# Severity ordering (P1 = most severe). "varies" sorts last.
_SEV_RANK = {"p1": 1, "p2": 2, "p3": 3, "p4": 4, "p5": 5, "varies": 6}


def severity_rank(sev: str) -> int:
    return _SEV_RANK.get(sev.lower(), 9)


@lru_cache(maxsize=1)
def _by_category() -> dict[str, list[VrtEntry]]:
    out: dict[str, list[VrtEntry]] = {}
    for e in load():
        out.setdefault(e.category, []).append(e)
    return out


def categories() -> list[str]:
    return sorted(_by_category())


def lookup(category: str = "", name: str = "", variant: str = "") -> VrtEntry | None:
    """Best-effort match of a free-text (category/name/variant) to a VRT row."""
    want = _slug(category, name, variant)
    best = None
    for e in load():
        if e.vrt_id == want:
            return e
        # partial containment fallback
        if category and category.lower() in e.category.lower():
            if not name or (name.lower() in e.name.lower()):
                best = best or e
    return best
