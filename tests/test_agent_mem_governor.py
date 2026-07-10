"""Unit tests for agentic apply_memory_governor (Part 3).

Ratio-scales fireteam/plan concurrency to available RAM, emits [RESOURCE-CAP],
fail-open. Loaded via importlib under a unique name to avoid clashing with the
recon `project_settings` module in a shared test run.
Run: python3 -m unittest tests.test_agent_mem_governor
"""
import importlib.util
import io
import os
import sys
import unittest
from contextlib import redirect_stdout

ROOT = os.path.join(os.path.dirname(__file__), '..')
# graph_db on path so the governor's `import resource_governor` fallback resolves.
sys.path.insert(0, os.path.join(ROOT, 'graph_db'))
import resource_governor as rg

# Load agentic/project_settings.py under a distinct module name.
_spec = importlib.util.spec_from_file_location(
    'agent_project_settings', os.path.join(ROOT, 'agentic', 'project_settings.py'))
aps = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(aps)

GB = 1024 ** 3


class AgentGovTestBase(unittest.TestCase):
    def setUp(self):
        os.environ.pop('NISARGHUNTER_MEM_GOVERNOR', None)
        rg.set_mem_override(None, None)
        rg.reset_profile_cache()

    def tearDown(self):
        rg.set_mem_override(None, None)


class TestByteBudgetScaling(AgentGovTestBase):
    def test_reduces_under_pressure(self):
        # 2GB free x 0.5 fraction = 1GB budget. member=512MB -> 2, tool=400MB -> 2.
        rg.set_mem_override(32 * GB, 2 * GB)
        s = {'FIRETEAM_MAX_CONCURRENT': 5, 'FIRETEAM_MAX_MEMBERS': 5,
             'PLAN_MAX_PARALLEL_TOOLS': 10}
        out = aps.apply_memory_governor(s)
        self.assertEqual(out['FIRETEAM_MAX_CONCURRENT'], 2)
        self.assertEqual(out['PLAN_MAX_PARALLEL_TOOLS'], 2)
        # membership is NOT scaled (would truncate a planned fireteam across resume)
        self.assertEqual(out['FIRETEAM_MAX_MEMBERS'], 5)

    def test_small_host_moderate_pressure_still_throttles(self):
        # The ratio-model bug: 4GB total / 2GB free is ratio 0.5 -> ratio said no
        # throttle. Byte-budget still caps (1GB budget / 512MB = 2 members).
        rg.set_mem_override(4 * GB, 2 * GB)
        out = aps.apply_memory_governor({'FIRETEAM_MAX_CONCURRENT': 5})
        self.assertEqual(out['FIRETEAM_MAX_CONCURRENT'], 2)

    def test_unchanged_when_ample(self):
        rg.set_mem_override(64 * GB, 60 * GB)  # 30GB budget -> everything fits
        s = {'FIRETEAM_MAX_CONCURRENT': 5, 'PLAN_MAX_PARALLEL_TOOLS': 10}
        out = aps.apply_memory_governor(dict(s))
        self.assertEqual(out, s)

    def test_floor_never_zero(self):
        rg.set_mem_override(32 * GB, 256 * 1024 * 1024)  # tiny
        out = aps.apply_memory_governor({'FIRETEAM_MAX_CONCURRENT': 5})
        self.assertGreaterEqual(out['FIRETEAM_MAX_CONCURRENT'], 1)


class TestGuards(AgentGovTestBase):
    def test_governor_off(self):
        os.environ['NISARGHUNTER_MEM_GOVERNOR'] = 'false'
        rg.set_mem_override(32 * GB, 1 * GB)
        s = {'FIRETEAM_MAX_CONCURRENT': 5, 'PLAN_MAX_PARALLEL_TOOLS': 10}
        out = aps.apply_memory_governor(dict(s))
        self.assertEqual(out, s)

    def test_non_targeted_keys_untouched(self):
        rg.set_mem_override(32 * GB, 2 * GB)
        s = {'FIRETEAM_ENABLED': True, 'OPENAI_MODEL': 'claude', 'MAX_ITERATIONS': 100}
        out = aps.apply_memory_governor(s)
        self.assertIs(out['FIRETEAM_ENABLED'], True)
        self.assertEqual(out['OPENAI_MODEL'], 'claude')
        self.assertEqual(out['MAX_ITERATIONS'], 100)  # not in governor map


class TestCapLog(AgentGovTestBase):
    def test_emits_on_reduction(self):
        rg.set_mem_override(32 * GB, 2 * GB)
        buf = io.StringIO()
        with redirect_stdout(buf):
            aps.apply_memory_governor({'FIRETEAM_MAX_CONCURRENT': 5})
        out = buf.getvalue()
        self.assertIn('[RESOURCE-CAP]', out)
        self.assertIn('FIRETEAM_MAX_CONCURRENT', out)

    def test_silent_when_ample(self):
        rg.set_mem_override(32 * GB, 32 * GB)
        buf = io.StringIO()
        with redirect_stdout(buf):
            aps.apply_memory_governor({'PLAN_MAX_PARALLEL_TOOLS': 10})
        self.assertNotIn('[RESOURCE-CAP]', buf.getvalue())


if __name__ == "__main__":
    unittest.main()
