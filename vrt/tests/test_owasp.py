"""Tests for the OWASP Top 10 (Web 2021 + API 2023) coverage map.

Run: python -m unittest vrt.tests.test_owasp -v
"""
import re
import unittest
from pathlib import Path

from vrt.owasp import ALL, API_2023, PARTIAL, STATIC, WEB_2021, report

# The set of rule ids the OWASP map claims code_audit provides. Every one of
# these MUST exist in the scanner, or the map is lying about coverage.
_SCANNER_SRC = (Path(__file__).resolve().parents[2] / "code_audit" / "scanner.py").read_text()
_REAL_RULES = set(re.findall(r'"(CA-[A-Z0-9-]+)"', _SCANNER_SRC))


class TestOwaspMap(unittest.TestCase):
    def test_has_all_20_categories(self):
        self.assertEqual(len(WEB_2021), 10)
        self.assertEqual(len(API_2023), 10)
        self.assertEqual(len(ALL), 20)

    def test_ids_are_unique_and_well_formed(self):
        ids = [c.id for c in ALL]
        self.assertEqual(len(ids), len(set(ids)), "duplicate OWASP ids")
        for c in WEB_2021:
            self.assertRegex(c.id, r"^A\d{2}$")
        for c in API_2023:
            self.assertRegex(c.id, r"^API\d{1,2}$")

    def test_tiers_are_valid(self):
        for c in ALL:
            self.assertIn(c.tier, ("static", "partial", "dynamic", "manual"))

    def test_every_ca_rule_referenced_actually_exists(self):
        # Guards against the map advertising a detector the scanner doesn't have.
        for c in ALL:
            for d in c.detectors:
                if d.startswith("CA-"):
                    self.assertIn(d, _REAL_RULES,
                                  f"{c.id} references {d}, which is not a real scanner rule")

    def test_static_partial_categories_name_at_least_one_real_rule(self):
        for c in ALL:
            if c.tier in (STATIC, PARTIAL):
                ca = [d for d in c.detectors if d.startswith("CA-")]
                # A03/A05/API3/etc. must be backed by a concrete rule, not just
                # a hand-wave to "web_probe".
                self.assertTrue(ca or "iac_scan" in c.detectors or "secret_scanner" in c.detectors
                                or "contract_audit" in c.detectors,
                                f"{c.id} claims {c.tier} coverage but names no concrete detector")

    def test_report_totals_add_up(self):
        rep = report()
        self.assertEqual(sum(rep["byTier"].values()), rep["total"])
        self.assertEqual(rep["total"], 20)
        # We should honestly cover most (not all) categories from source.
        self.assertGreaterEqual(rep["withStaticCoverage"], 12)


if __name__ == "__main__":
    unittest.main()
