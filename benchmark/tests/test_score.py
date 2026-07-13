"""Unit tests for the guinea-pig benchmark scorer.

Run: python -m unittest benchmark.tests.test_score -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from score import load_ground_truth, score, _finding_matches


class TestMatching(unittest.TestCase):
    def test_category_match(self):
        item = {"category": "sqli", "keywords": ["sql injection"], "endpoint": ""}
        self.assertTrue(_finding_matches(item, {"category": "sqli", "title": "whatever"}))

    def test_keyword_match_in_title(self):
        item = {"category": "sqli", "keywords": ["sql injection"], "endpoint": ""}
        self.assertTrue(_finding_matches(item, {"category": "x", "title": "SQL Injection found"}))

    def test_endpoint_constraint_excludes_wrong_path(self):
        item = {"category": "idor", "keywords": ["idor"], "endpoint": "/api/v2/notes/"}
        self.assertFalse(_finding_matches(item, {"category": "idor", "endpoint": "/api/v2/users/"}))
        self.assertTrue(_finding_matches(item, {"category": "idor", "endpoint": "/api/v2/notes/5"}))

    def test_no_signal_no_match(self):
        item = {"category": "sqli", "keywords": ["sql injection"], "endpoint": ""}
        self.assertFalse(_finding_matches(item, {"category": "xss", "title": "reflected xss"}))


class TestScoring(unittest.TestCase):
    def setUp(self):
        self.gt = load_ground_truth()
        self.all_items = [it for t in self.gt["targets"].values() for it in t["items"]]

    def test_perfect_recall(self):
        perfect = [{"category": it["category"], "title": it["name"], "endpoint": it.get("endpoint", "")}
                   for it in self.all_items]
        r = score(self.gt, perfect)
        self.assertEqual(len(r["misses"]), 0)
        self.assertEqual(len(r["hits"]), len(self.all_items))

    def test_empty_findings_zero_recall(self):
        r = score(self.gt, [])
        self.assertEqual(len(r["hits"]), 0)
        self.assertEqual(len(r["misses"]), len(self.all_items))

    def test_p1_only_scan(self):
        p1 = [{"category": it["category"], "title": it["name"], "endpoint": it.get("endpoint", "")}
              for it in self.all_items if it["p_tier"] == "P1"]
        r = score(self.gt, p1)
        self.assertGreater(r["hit_tiers"]["P1"], 0)
        self.assertEqual(r["hit_tiers"]["P4"], 0)

    def test_ground_truth_is_well_formed(self):
        for t in self.gt["targets"].values():
            for it in t["items"]:
                self.assertIn(it["p_tier"], ["P1", "P2", "P3", "P4", "P5"])
                self.assertTrue(it.get("keywords"), f"{it['id']} needs keywords")


if __name__ == "__main__":
    unittest.main()
