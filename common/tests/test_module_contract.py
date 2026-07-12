"""Tests for the module contract, registry, and built-in adapters
(master-plan Phase 2, Priority 6).

Run: python -m unittest common.tests.test_module_contract -v
"""

import asyncio
import unittest

from common.module_contract import (
    ExecutionContext, ModuleCategory, NormalizedResult, CancelToken,
)
from common.module_registry import ModuleRegistry
from common.adapters.builtin_adapters import register_builtin_modules, ReconAdapter


class TestRegistry(unittest.TestCase):
    def test_register_and_lookup(self):
        reg = ModuleRegistry()
        reg.register(ReconAdapter())
        self.assertIsNotNone(reg.get("recon"))
        self.assertEqual(reg.get("recon").metadata().category, ModuleCategory.RECON)

    def test_duplicate_registration_rejected(self):
        reg = ModuleRegistry()
        reg.register(ReconAdapter())
        with self.assertRaises(ValueError):
            reg.register(ReconAdapter())

    def test_register_builtins_is_idempotent(self):
        reg = ModuleRegistry()
        register_builtin_modules(reg)
        n = len(reg.metadata())
        register_builtin_modules(reg)                     # second call must not double
        self.assertEqual(len(reg.metadata()), n)
        self.assertEqual(n, 7)                             # all seven built-ins

    def test_by_category(self):
        reg = register_builtin_modules(ModuleRegistry())
        recon = {m.metadata().name for m in reg.by_category(ModuleCategory.RECON)}
        self.assertIn("recon", recon)
        self.assertIn("cloud_recon", recon)

    def test_for_tech_is_technology_aware(self):
        reg = register_builtin_modules(ModuleRegistry())
        names = {m.metadata().name for m in reg.for_tech("Terraform")}   # case-insensitive
        self.assertIn("iac_scan", names)
        self.assertNotIn("cloud_recon", names)


class TestAdapterContract(unittest.TestCase):
    def test_validate_config_requires_program_and_scope(self):
        a = ReconAdapter()
        bad = a.validate_config({})
        self.assertFalse(bad.ok)
        self.assertTrue(any("program_id" in e for e in bad.errors))
        good = a.validate_config({"program_id": "p1", "scope": ["acme.com"]})
        self.assertTrue(good.ok)

    def test_normalize_result_passthrough_and_dict(self):
        a = ReconAdapter()
        nr = a.normalize_result(NormalizedResult(summary="x"))
        self.assertEqual(nr.summary, "x")
        nr2 = a.normalize_result({"findings": [{"id": 1}], "summary": "s"})
        self.assertEqual(len(nr2.findings), 1)
        self.assertEqual(nr2.summary, "s")

    def test_validation_signals_confidence_scales_with_findings(self):
        a = ReconAdapter()
        self.assertEqual(a.validation_signals(NormalizedResult()).confidence, 0.0)
        self.assertGreater(a.validation_signals(NormalizedResult(findings=[{"x": 1}])).confidence, 0.0)

    def test_execute_yields_delegation_event(self):
        a = ReconAdapter()
        ctx = ExecutionContext(program_id="p1", workspace_id="w1", user_id="u1", scope=["acme.com"])

        async def run():
            return [e async for e in a.execute(ctx)]

        events = asyncio.run(run())
        self.assertTrue(events)
        self.assertIn("/recon/start", events[0].data.get("route", ""))

    def test_execute_honors_cancel_token(self):
        a = ReconAdapter()
        tok = CancelToken(); tok.cancel()
        ctx = ExecutionContext(program_id="p1", workspace_id=None, user_id="u1", scope=["x"], cancel_token=tok)

        async def run():
            return [e async for e in a.execute(ctx)]

        events = asyncio.run(run())
        self.assertEqual(events[0].level, "warning")


if __name__ == "__main__":
    unittest.main()
