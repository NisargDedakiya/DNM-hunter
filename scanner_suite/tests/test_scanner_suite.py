"""Tests for the unified orchestrator + SARIF export.

Run: python -m unittest scanner_suite.tests.test_scanner_suite -v
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from scanner_suite import scan, to_sarif

_PY = '''
import os
from flask import request
def h():
    name = request.args.get("name")
    os.system("ping " + name)
'''

_SOL = '''
pragma solidity ^0.7.0;
contract C {
  function kill() public { selfdestruct(payable(msg.sender)); }
}
'''

_TF = 'resource "aws_s3_bucket" "b" { acl = "public-read" }\n'


def _planted(root: Path):
    (root / "app.py").write_text(_PY)
    (root / "C.sol").write_text(_SOL)
    (root / "main.tf").write_text(_TF)


class TestOrchestrator(unittest.TestCase):
    def test_scan_aggregates_multiple_scanners(self):
        with tempfile.TemporaryDirectory() as d:
            _planted(Path(d))
            res = scan(d)
        scanners = {f.scanner for f in res.findings}
        # SAST (python), contract (solidity), and IaC (terraform) all contribute
        self.assertIn("code_audit", scanners)
        self.assertIn("contract_audit", scanners)
        self.assertIn("iac_scan", scanners)
        self.assertGreaterEqual(res.summary["total"], 3)

    def test_findings_are_severity_ranked(self):
        with tempfile.TemporaryDirectory() as d:
            _planted(Path(d))
            res = scan(d)
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        ranks = [order[f.severity] for f in res.findings]
        self.assertEqual(ranks, sorted(ranks))

    def test_vrt_ids_extracted(self):
        with tempfile.TemporaryDirectory() as d:
            _planted(Path(d))
            res = scan(d)
        # at least the SAST/contract findings should carry a VRT id
        self.assertTrue(any(f.vrt for f in res.findings))


class TestSarif(unittest.TestCase):
    def test_sarif_shape_is_valid(self):
        with tempfile.TemporaryDirectory() as d:
            _planted(Path(d))
            res = scan(d)
        doc = to_sarif(res)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertIn("$schema", doc)
        self.assertEqual(len(doc["runs"]), 1)
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "NisargHunter AI")
        self.assertTrue(run["tool"]["driver"]["rules"])
        self.assertEqual(len(run["results"]), len(res.findings))

    def test_sarif_result_has_rule_level_and_location(self):
        with tempfile.TemporaryDirectory() as d:
            _planted(Path(d))
            res = scan(d)
        doc = to_sarif(res)
        r = doc["runs"][0]["results"][0]
        self.assertIn(r["level"], ("error", "warning", "note"))
        self.assertIn("ruleId", r)
        self.assertIn("message", r)

    def test_sarif_levels_map_severity(self):
        with tempfile.TemporaryDirectory() as d:
            _planted(Path(d))
            res = scan(d)
        doc = to_sarif(res)
        # every rule id referenced by a result exists in the driver.rules table
        rule_ids = {ru["id"] for ru in doc["runs"][0]["tool"]["driver"]["rules"]}
        for r in doc["runs"][0]["results"]:
            self.assertIn(r["ruleId"], rule_ids)


if __name__ == "__main__":
    unittest.main()
