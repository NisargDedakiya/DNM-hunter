"""Tests for the CVSS + tech-stack impact engine.

Run: python -m unittest common.impact.tests.test_impact -v
"""
import unittest

from common.impact.cvss import base_score, parse_vector, severity_rating, InvalidVector
from common.impact.tech_impact import ExposureContext, assess_contextual_impact
from common.impact.assessor import assess, build_grounding_prompt, narrate


class TestCvss(unittest.TestCase):
    def test_published_reference_vectors(self):
        cases = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,   # Log4Shell
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,    # unauth RCE
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,    # info disclosure
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N": 3.1,    # low reflected
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,    # no impact
        }
        for vec, exp in cases.items():
            self.assertAlmostEqual(base_score(vec).base_score, exp, places=1, msg=vec)

    def test_severity_bands(self):
        self.assertEqual(severity_rating(0.0), "None")
        self.assertEqual(severity_rating(3.9), "Low")
        self.assertEqual(severity_rating(4.0), "Medium")
        self.assertEqual(severity_rating(7.0), "High")
        self.assertEqual(severity_rating(9.0), "Critical")

    def test_bare_vector_without_prefix(self):
        self.assertAlmostEqual(base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").base_score, 9.8, places=1)

    def test_invalid_vectors_raise(self):
        with self.assertRaises(InvalidVector):
            parse_vector("AV:N/AC:L")          # missing metrics
        with self.assertRaises(InvalidVector):
            base_score("AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")  # bad value


class TestTechImpact(unittest.TestCase):
    def test_ssrf_on_cloud_escalates(self):
        internal = assess_contextual_impact("ssrf", 8.6, ["nginx"], ExposureContext(cloud_hosted=False, internet_facing=True))
        cloud = assess_contextual_impact("ssrf", 8.6, ["aws", "ec2"], ExposureContext(cloud_hosted=True, internet_facing=True))
        self.assertGreater(cloud.contextual_score, internal.contextual_score)
        self.assertTrue(any("metadata" in f.rationale.lower() for f in cloud.factors))

    def test_internal_only_reduces_score(self):
        # Use info-disclosure (no lateral-movement offset) and a mid base so the
        # reduction is visible rather than clamped. Internal RCE deliberately
        # stays high because of the lateral-movement escalation — tested separately.
        ext = assess_contextual_impact("information_disclosure", 5.3, [], ExposureContext(internet_facing=True, authentication_required=True))
        intn = assess_contextual_impact("information_disclosure", 5.3, [], ExposureContext(internet_facing=False, authentication_required=True))
        self.assertLess(intn.contextual_score, ext.contextual_score)

    def test_internal_rce_stays_critical_due_to_lateral_movement(self):
        intn = assess_contextual_impact("rce", 9.8, [], ExposureContext(internet_facing=False))
        self.assertTrue(any("lateral" in f.name for f in intn.factors))
        self.assertGreaterEqual(intn.contextual_score, 9.0)   # still Critical

    def test_sqli_with_database_escalates(self):
        r = assess_contextual_impact("sqli", 7.0, ["mysql", "php"], ExposureContext())
        self.assertTrue(any("database" in f.name for f in r.factors))
        self.assertGreater(r.contextual_score, 7.0)

    def test_score_is_clamped(self):
        r = assess_contextual_impact("ssrf", 9.5, ["aws"], ExposureContext(cloud_hosted=True, handles_sensitive_data=True))
        self.assertLessEqual(r.contextual_score, 10.0)
        r2 = assess_contextual_impact("open redirect", 0.5, [], ExposureContext(internet_facing=False, authentication_required=True))
        self.assertGreaterEqual(r2.contextual_score, 0.0)


class TestAssessor(unittest.TestCase):
    def test_assess_from_vector(self):
        a = assess("ssrf", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                   tech_stack=["aws"], exposure=ExposureContext(cloud_hosted=True), cve_ids=["CVE-2024-1"])
        self.assertEqual(a.contextual.base_score, 7.5)
        self.assertGreater(a.contextual.contextual_score, 7.5)   # cloud SSRF escalation
        self.assertIn("CVE-2024-1", a.to_dict()["cveIds"])

    def test_assess_falls_back_to_category_default(self):
        a = assess("rce")   # no vector, no score
        self.assertEqual(a.contextual.base_score, 9.8)

    def test_invalid_vector_falls_back_to_score(self):
        a = assess("xss", cvss_vector="garbage", cvss_score=6.1)
        self.assertEqual(a.contextual.base_score, 6.1)

    def test_grounding_prompt_contains_fixed_facts(self):
        a = assess("sqli", cvss_score=8.8, tech_stack=["mysql"])
        p = build_grounding_prompt(a, "SQLi in /login")
        self.assertIn("Do NOT invent", p)
        self.assertIn("8.8", p)
        self.assertIn("mysql", p)

    def test_narrate_uses_llm_and_survives_failure(self):
        a = assess("rce", cvss_score=9.8)
        narrate(a, lambda prompt: "Attacker gets shell.", "cmd injection")
        self.assertEqual(a.narrative, "Attacker gets shell.")

        b = assess("rce", cvss_score=9.8)
        def boom(_): raise RuntimeError("llm down")
        narrate(b, boom)
        self.assertEqual(b.narrative, "")   # deterministic result preserved


if __name__ == "__main__":
    unittest.main()
