"""Tests for the professional report generator.

Run: python -m unittest report_gen.tests.test_report_gen -v
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from report_gen import build_report, enrich, guidance_for, to_html, to_markdown
from scanner_suite import scan


def _planted(root: Path):
    (root / "app.py").write_text(
        "import os\nfrom flask import request\n"
        "def h():\n    n = request.args.get('n')\n    os.system('ping ' + n)\n"
    )
    (root / "C.sol").write_text(
        "pragma solidity ^0.7.0;\ncontract C {\n"
        "  function kill() public { selfdestruct(payable(msg.sender)); }\n}\n"
    )


class TestKnowledge(unittest.TestCase):
    def test_curated_rule_has_real_guidance(self):
        g = guidance_for("CA-SQLI", "critical")
        self.assertIn("parameteris", g.remediation.lower())
        self.assertTrue(g.cvss_vector.startswith("CVSS:3.1/"))
        self.assertTrue(any("CWE-89" in r for r in g.references))

    def test_family_prefix_lookup(self):
        # composite ids like "LLM05:LLM-051" fall back to family, then severity
        g = guidance_for("SC-REENTRANCY", "critical")
        self.assertIn("SWC-107", " ".join(g.references))

    def test_unknown_rule_falls_back_by_severity(self):
        g = guidance_for("ZZ-UNKNOWN", "high")
        self.assertTrue(g.cvss_vector.startswith("CVSS:3.1/"))


class TestEnrichment(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        _planted(Path(self.tmp.name))
        self.result = scan(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_cvss_scored(self):
        ef = enrich(self.result.findings)
        self.assertTrue(ef)
        # command injection should score critical (9.8) via the CVSS engine
        cmdi = [f for f in ef if f.rule_id == "CA-CMDI"]
        self.assertTrue(cmdi)
        self.assertGreaterEqual(cmdi[0].cvss_score, 9.0)

    def test_sorted_by_severity_then_cvss(self):
        ef = enrich(self.result.findings)
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        ranks = [order[f.severity] for f in ef]
        self.assertEqual(ranks, sorted(ranks))


class TestRender(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        _planted(Path(self.tmp.name))
        self.report = build_report(scan(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_markdown_has_sections(self):
        md = to_markdown(self.report)
        self.assertIn("# Security Assessment Report", md)
        self.assertIn("## Executive summary", md)
        self.assertIn("## Detailed findings", md)
        self.assertIn("Remediation.", md)
        self.assertIn("CVSS v3.1", md)

    def test_html_is_self_contained_and_escaped(self):
        h = to_html(self.report)
        self.assertTrue(h.lstrip().startswith("<!doctype html>"))
        self.assertIn("<style>", h)
        self.assertNotIn("http://", h.split("<style>")[0])  # no external head resources
        # HTML is escaped — no raw script injection from a finding title
        self.assertNotIn("<script>", h)

    def test_report_summary_counts(self):
        self.assertGreaterEqual(self.report.summary["total"], 2)
        self.assertEqual(self.report.summary["highestSeverity"], "critical")


if __name__ == "__main__":
    unittest.main()
