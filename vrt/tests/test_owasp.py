"""Tests for the OWASP coverage map (Web 2021 + API 2023 + Mobile 2024 + LLM 2025).

Run: python -m unittest vrt.tests.test_owasp -v
"""
import re
import unittest
from pathlib import Path

from vrt.owasp import ALL, API_2023, LLM_2025, MOBILE_2024, PARTIAL, STATIC, WEB_2021, report

_ROOT = Path(__file__).resolve().parents[2]


def _rules_in(path: str, prefix: str) -> set[str]:
    src = (_ROOT / path).read_text()
    return set(re.findall(rf'"({prefix}[A-Z0-9-]+)"', src))


# Every rule id the map advertises MUST exist in the real scanner, or the map is
# lying about coverage. Validate each detector family against its scanner source.
_REAL = {
    "CA-": _rules_in("code_audit/scanner.py", "CA-"),
    "MA-": _rules_in("mobile_audit/scanner.py", "MA-"),
    "LLM-": _rules_in("llm_audit/scanner.py", "LLM-"),
}


class TestOwaspMap(unittest.TestCase):
    def test_has_all_forty_categories(self):
        self.assertEqual(len(WEB_2021), 10)
        self.assertEqual(len(API_2023), 10)
        self.assertEqual(len(MOBILE_2024), 10)
        self.assertEqual(len(LLM_2025), 10)
        self.assertEqual(len(ALL), 40)

    def test_ids_are_unique_within_each_family(self):
        for fam in (WEB_2021, API_2023, MOBILE_2024, LLM_2025):
            ids = [c.id for c in fam]
            self.assertEqual(len(ids), len(set(ids)), "duplicate OWASP ids")
        for c in MOBILE_2024:
            self.assertRegex(c.id, r"^M\d{1,2}$")
        for c in LLM_2025:
            self.assertRegex(c.id, r"^LLM\d{2}$")

    def test_tiers_are_valid(self):
        for c in ALL:
            self.assertIn(c.tier, ("static", "partial", "dynamic", "manual"))

    def test_every_referenced_rule_actually_exists(self):
        # Guards against the map advertising a detector that no scanner provides.
        for c in ALL:
            for d in c.detectors:
                for prefix, real in _REAL.items():
                    if d.startswith(prefix):
                        self.assertIn(d, real,
                                      f"{c.id} references {d}, not a real scanner rule")

    def test_static_partial_categories_name_a_concrete_detector(self):
        modules = {"iac_scan", "secret_scanner", "contract_audit", "binary_audit",
                   "mobile_scan", "ai_attack_surface"}
        for c in ALL:
            if c.tier in (STATIC, PARTIAL):
                rule_backed = any(d.startswith(("CA-", "MA-", "LLM-")) for d in c.detectors)
                self.assertTrue(rule_backed or modules.intersection(c.detectors),
                                f"{c.id} claims {c.tier} but names no concrete detector")

    def test_report_totals_add_up(self):
        rep = report()
        self.assertEqual(sum(rep["byTier"].values()), rep["total"])
        self.assertEqual(rep["total"], 40)
        # Most categories across all four lists have source-visible coverage.
        self.assertGreaterEqual(rep["withStaticCoverage"], 24)


if __name__ == "__main__":
    unittest.main()
