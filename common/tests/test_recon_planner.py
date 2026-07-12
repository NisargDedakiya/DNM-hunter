"""Tests for the recon planner (master-plan Phase 3, Priority 2).

Run: python -m unittest common.tests.test_recon_planner -v
"""

import unittest

from common.module_registry import ModuleRegistry
from common.adapters.builtin_adapters import register_builtin_modules
from common.recon_planner import ReconPlanner


def _planner():
    return ReconPlanner(register_builtin_modules(ModuleRegistry()))


class TestReconPlanner(unittest.TestCase):
    def test_plan_only_references_existing_modules(self):
        reg = register_builtin_modules(ModuleRegistry())
        plan = ReconPlanner(reg).build_plan(assets=["acme.com"])
        known = {m.name for m in reg.metadata()}
        for step in plan.steps:
            self.assertIn(step.module_name, known)

    def test_technology_match_is_prioritized_high(self):
        plan = _planner().build_plan(detected_tech=["terraform"], assets=["repo"])
        by_name = {s.module_name: s for s in plan.steps}
        self.assertEqual(by_name["iac_scan"].priority, "high")
        self.assertIn("terraform", by_name["iac_scan"].rationale.lower())

    def test_no_tech_leads_with_recon_medium_not_scanner_low(self):
        plan = _planner().build_plan(assets=["acme.com"])
        by_name = {s.module_name: s for s in plan.steps}
        self.assertEqual(by_name["recon"].priority, "medium")

    def test_steps_sorted_high_priority_first(self):
        plan = _planner().build_plan(detected_tech=["graphql"], assets=["acme.com"])
        ranks = ["high", "medium", "low"]
        seen = [ranks.index(s.priority) for s in plan.steps]
        self.assertEqual(seen, sorted(seen))            # non-decreasing priority

    def test_target_assets_propagate_to_steps(self):
        plan = _planner().build_plan(assets=["a.com", "b.com"])
        for s in plan.steps:
            self.assertEqual(s.target_assets, ["a.com", "b.com"])

    def test_reasoning_mentions_detected_tech(self):
        plan = _planner().build_plan(detected_tech=["WordPress"], assets=["acme.com"])
        self.assertIn("wordpress", plan.reasoning.lower())

    def test_category_filter(self):
        from common.module_contract import ModuleCategory
        plan = _planner().build_plan(assets=["x"], include_categories=[ModuleCategory.RECON])
        cats = {s.module_name for s in plan.steps}
        self.assertIn("recon", cats)
        self.assertNotIn("nuclei", cats)                 # scanner filtered out
        self.assertNotIn("gvm_scan", cats)

    def test_to_dict_shape(self):
        plan = _planner().build_plan(detected_tech=["graphql"], assets=["x"])
        d = plan.to_dict()
        self.assertIn("steps", d)
        self.assertIn("reasoning", d)
        self.assertIn("moduleName", d["steps"][0])
        self.assertIn("estimatedValue", d["steps"][0])


if __name__ == "__main__":
    unittest.main()
