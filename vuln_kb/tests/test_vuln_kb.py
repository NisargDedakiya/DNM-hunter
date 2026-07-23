"""Tests for the vulnerability knowledge base.

Beyond shape checks, these enforce that the KB does not *lie*: every OWASP id,
verification oracle and CA-*/MA-*/LLM-* rule it references must actually exist in
the real modules. A knowledge base that points at detectors we don't have is
worse than none.

Run: python -m unittest vuln_kb.tests.test_vuln_kb -v
"""
import re
import unittest
from pathlib import Path

from vuln_kb import KB, compose_risk, get

_ROOT = Path(__file__).resolve().parents[2]
_VALID_VERIFY = {"timing", "boolean", "reflection", "oast", "differential", "static", "manual"}
_VALID_SEV = {"critical", "high", "medium", "low"}
_VALID_CONF = {"firm", "tentative", "heuristic", "dynamic-only"}


def _rules_in(path: str, prefix: str) -> set[str]:
    src = (_ROOT / path).read_text()
    return set(re.findall(rf'"({prefix}[A-Z0-9-]+)"', src))


_REAL_RULES = (_rules_in("code_audit/scanner.py", "CA-")
               | _rules_in("mobile_audit/scanner.py", "MA-")
               | _rules_in("llm_audit/scanner.py", "LLM-"))
_OWASP_SRC = (_ROOT / "vrt" / "owasp.py").read_text()
_REAL_OWASP = set(re.findall(r'OwaspCategory\("([A-Z0-9]+)"', _OWASP_SRC))


class TestShape(unittest.TestCase):
    def test_covers_the_named_classes(self):
        for name in ("SQL Injection", "XSS", "IDOR", "SSRF", "Authentication issues",
                     "JWT problems", "File upload vulnerabilities", "API security issues",
                     "Logic flaws"):
            self.assertIsNotNone(get(name.replace("issues", "").replace("vulnerabilities", "")
                                     .replace("security", "").strip()) or _by_keyword(name),
                                 f"KB should cover '{name}'")

    def test_ids_unique(self):
        ids = [v.id for v in KB]
        self.assertEqual(len(ids), len(set(ids)))

    def test_fields_valid(self):
        for v in KB:
            self.assertIn(v.severity, _VALID_SEV, v.id)
            self.assertIn(v.verify.method, _VALID_VERIFY, v.id)
            self.assertIn(v.static_confidence, _VALID_CONF, v.id)
            self.assertRegex(v.cwe, r"^CWE-\d+$")
            self.assertTrue(v.payloads and v.evidence and v.remediation, v.id)


class TestNoLies(unittest.TestCase):
    def test_owasp_ids_exist(self):
        for v in KB:
            for oid in (v.owasp_web, v.owasp_api):
                if oid:
                    self.assertIn(oid, _REAL_OWASP, f"{v.id} references OWASP {oid}, not in the map")

    def test_referenced_rules_exist(self):
        # Greedy match of a full rule token; '/' is not in the class so the
        # "CA-HASH/CA-CIPHER/…" shorthand splits into separate matches naturally.
        rule_re = re.compile(r"(?:CA|MA|LLM)-[A-Z0-9]+(?:-[A-Z0-9]+)*")
        for v in KB:
            for eng in v.engines:
                for rule in rule_re.findall(eng):
                    self.assertIn(rule, _REAL_RULES,
                                  f"{v.id} references {rule}, not a real detector rule")


class TestRiskScoring(unittest.TestCase):
    def test_verified_exploit_scores_highest(self):
        lead = compose_risk("critical", confidence="heuristic")["score"]
        verified = compose_risk("critical", confidence="heuristic", exploit_verified=True)["score"]
        self.assertGreater(verified, lead)

    def test_confidence_lowers_score(self):
        firm = compose_risk("high", confidence="firm")["score"]
        heuristic = compose_risk("high", confidence="heuristic")["score"]
        self.assertGreater(firm, heuristic)

    def test_bands_and_bounds(self):
        r = compose_risk("critical", confidence="firm", exploit_verified=True, epss=0.9)
        self.assertLessEqual(r["score"], 10.0)
        self.assertEqual(r["band"], "critical")
        self.assertEqual(compose_risk("low", confidence="heuristic")["band"], "low")


def _by_keyword(name: str):
    n = name.lower()
    for v in KB:
        if any(w in v.name.lower() for w in n.split()):
            return v
    return None


if __name__ == "__main__":
    unittest.main()
