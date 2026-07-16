"""Tests for the VRT taxonomy + coverage map.

Run: python -m unittest vrt.tests.test_vrt -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from vrt import load, lookup, classify, coverage_report
from vrt.coverage import STATIC, DYNAMIC, MANUAL, OUT


class TestTaxonomy(unittest.TestCase):
    def test_loads_full_taxonomy(self):
        e = load()
        self.assertGreater(len(e), 390)                       # ~400 VRT rows
        self.assertEqual(len({x.vrt_id for x in e}), len(e))  # ids unique

    def test_severity_normalised(self):
        sevs = {e.severity for e in load()}
        self.assertTrue(sevs <= {"p1", "p2", "p3", "p4", "p5", "varies"})

    def test_lookup_partial(self):
        e = lookup("Server-Side Injection", "SQL Injection")
        self.assertIsNotNone(e)
        self.assertEqual(e.severity, "p1")


class TestCoverage(unittest.TestCase):
    def test_injection_is_static(self):
        e = lookup("Server-Side Injection", "SQL Injection")
        self.assertEqual(classify(e).method, STATIC)
        self.assertIn("code_audit", classify(e).detector)

    def test_smart_contract_is_static(self):
        e = lookup("Smart Contract Misconfiguration", "Reentrancy Attack")
        self.assertEqual(classify(e).method, STATIC)
        self.assertIn("contract_audit", classify(e).detector)

    def test_automotive_out_of_scope(self):
        autos = [e for e in load() if "automotive" in e.category.lower()]
        self.assertTrue(autos)
        self.assertTrue(all(classify(e).method == OUT for e in autos))

    def test_access_control_is_dynamic(self):
        e = lookup("Broken Access Control (BAC)", "Insecure Direct Object References (IDOR)")
        self.assertEqual(classify(e).method, DYNAMIC)

    def test_report_totals_add_up(self):
        rep = coverage_report()
        self.assertEqual(sum(rep["byMethod"].values()), rep["total"])
        self.assertGreater(rep["byMethod"][STATIC], 100)   # real static coverage


if __name__ == "__main__":
    unittest.main()
