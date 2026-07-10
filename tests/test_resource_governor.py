"""Unit tests for graph_db/resource_governor.py (dual-cap memory governor).

Pure-stdlib, host-runnable: injects synthetic memory via set_mem_override so it
never depends on the real host. Run: python3 -m unittest tests.test_resource_governor
"""
import io
import os
import sys
import unittest
from contextlib import redirect_stdout

# Import the module directly (bypass graph_db/__init__.py, which pulls in neo4j).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'graph_db'))

import resource_governor as g

GB = 1024 ** 3


class GovernorTestBase(unittest.TestCase):
    def setUp(self):
        # Clean, deterministic env for every test.
        for k in ("NISARGHUNTER_MEM_GOVERNOR", "MEM_SCALE_HIGH", "MEM_SCALE_LOW",
                  "MEM_SCALE_FLOOR", "MEM_BUDGET_FRACTION", "MEM_SAFETY_TOLERANCE",
                  "MEM_READ_TTL_S", "RESOURCE_PROFILE_PATH"):
            os.environ.pop(k, None)
        g.set_mem_override(None, None)
        g.reset_profile_cache()
        g._cpu_last = None

    def tearDown(self):
        g.set_mem_override(None, None)
        g.reset_profile_cache()


class TestScale(GovernorTestBase):
    def test_full_scale_when_ample(self):
        g.set_mem_override(32 * GB, 20 * GB)  # ratio 0.625 >= HIGH 0.5
        self.assertEqual(g.scale(), 1.0)

    def test_floor_when_starved(self):
        g.set_mem_override(32 * GB, 2 * GB)  # ratio 0.0625 <= LOW 0.15
        self.assertAlmostEqual(g.scale(), 0.15, places=6)

    def test_linear_ramp_midband(self):
        # ratio exactly halfway between LOW(0.15) and HIGH(0.50) -> 0.325
        g.set_mem_override(100 * GB, 32.5 * GB)  # ratio 0.325
        s = g.scale()
        # frac=0.5 -> floor + 0.5*(1-floor) = 0.15 + 0.425 = 0.575
        self.assertAlmostEqual(s, 0.575, places=3)

    def test_monotonic_in_available(self):
        prev = -1.0
        for avail_gb in range(1, 33):
            g.set_mem_override(32 * GB, avail_gb * GB)
            s = g.scale()
            self.assertGreaterEqual(s, prev)
            prev = s

    def test_disabled_is_full(self):
        os.environ["NISARGHUNTER_MEM_GOVERNOR"] = "false"
        g.set_mem_override(32 * GB, 1 * GB)
        self.assertEqual(g.scale(), 1.0)

    def test_fail_open_when_unreadable(self):
        g.set_mem_override(None, None)
        orig = g._MEMINFO_PATH
        g._MEMINFO_PATH = "/proc/does-not-exist-xyz"
        g._mem_cache = None
        try:
            self.assertEqual(g.scale(), 1.0)  # fail open
            self.assertIsNone(g.read_mem())
        finally:
            g._MEMINFO_PATH = orig
            g._mem_cache = None


class TestScaled(GovernorTestBase):
    def test_never_exceeds_env(self):
        g.set_mem_override(32 * GB, 32 * GB)  # scale 1.0
        self.assertEqual(g.scaled(8, floor=1), 8)

    def test_reduces_under_pressure(self):
        g.set_mem_override(32 * GB, 2 * GB)  # scale 0.15
        # round(8 * 0.15) = round(1.2) = 1
        self.assertEqual(g.scaled(8, floor=1), 1)

    def test_respects_floor(self):
        g.set_mem_override(32 * GB, 2 * GB)  # scale 0.15
        self.assertEqual(g.scaled(8, floor=3), 3)

    def test_floor_capped_to_value(self):
        g.set_mem_override(32 * GB, 2 * GB)
        self.assertEqual(g.scaled(2, floor=10), 2)  # floor can't exceed value

    def test_zero_or_negative_passthrough(self):
        g.set_mem_override(32 * GB, 2 * GB)
        self.assertEqual(g.scaled(0), 0)

    def test_disabled_passthrough(self):
        os.environ["NISARGHUNTER_MEM_GOVERNOR"] = "0"
        g.set_mem_override(32 * GB, 1 * GB)
        self.assertEqual(g.scaled(50, floor=1), 50)


class TestScaledCap(GovernorTestBase):
    def test_fits_returns_env(self):
        # 2GB avail, 10% budget = ~214MB, /500 = ~429k >= 300k -> env
        g.set_mem_override(32 * GB, 2 * GB)
        self.assertEqual(g.scaled_cap(300000, 500, 0.10, 1000), 300000)

    def test_caps_when_tight(self):
        # 512MB avail, 10% = ~53.6MB, /500 = 107374 < 300000
        g.set_mem_override(32 * GB, 512 * 1024 * 1024)
        self.assertEqual(g.scaled_cap(300000, 500, 0.10, 1000), 107374)

    def test_never_exceeds_env_cap(self):
        g.set_mem_override(64 * GB, 64 * GB)
        self.assertEqual(g.scaled_cap(1000, 1, 0.10, 1), 1000)

    def test_respects_floor(self):
        g.set_mem_override(32 * GB, 1024)  # almost nothing free
        self.assertEqual(g.scaled_cap(300000, 500, 0.10, 1000), 1000)

    def test_bad_bytes_fail_open(self):
        g.set_mem_override(32 * GB, 512 * 1024 * 1024)
        self.assertEqual(g.scaled_cap(300000, 0, 0.10, 1000), 300000)
        self.assertEqual(g.scaled_cap(300000, -5, 0.10, 1000), 300000)

    def test_disabled_returns_env(self):
        os.environ["NISARGHUNTER_MEM_GOVERNOR"] = "false"
        g.set_mem_override(32 * GB, 512 * 1024 * 1024)
        self.assertEqual(g.scaled_cap(300000, 500, 0.10, 1000), 300000)


class TestPressure(GovernorTestBase):
    def test_ok(self):
        g.set_mem_override(32 * GB, 20 * GB)
        self.assertEqual(g.pressure(), "ok")

    def test_warn(self):
        g.set_mem_override(32 * GB, 10 * GB)  # ratio 0.3125 between LOW and HIGH
        self.assertEqual(g.pressure(), "warn")

    def test_critical(self):
        g.set_mem_override(32 * GB, 2 * GB)  # ratio 0.0625 <= LOW
        self.assertEqual(g.pressure(), "critical")


class TestMeminfoParser(GovernorTestBase):
    def test_parse_ok(self):
        text = "MemTotal:       32501176 kB\nMemFree: 100 kB\nMemAvailable:   21275704 kB\n"
        parsed = g._parse_meminfo(text)
        self.assertEqual(parsed, (32501176 * 1024, 21275704 * 1024))

    def test_parse_missing_available(self):
        self.assertIsNone(g._parse_meminfo("MemTotal: 100 kB\n"))

    def test_parse_garbage(self):
        self.assertIsNone(g._parse_meminfo("not meminfo at all"))


class TestCpu(GovernorTestBase):
    def test_first_call_zero(self):
        g._cpu_last = None
        # may read real /proc/stat; first call must be 0.0 regardless
        self.assertEqual(g.cpu_percent(), 0.0)

    def test_cores_positive(self):
        self.assertGreaterEqual(g.cpu_cores(), 1)


class TestProfile(GovernorTestBase):
    def test_fallback_used_when_no_file(self):
        os.environ["RESOURCE_PROFILE_PATH"] = "/tmp/nonexistent-profile-xyz.json"
        g.reset_profile_cache()
        self.assertEqual(g.bytes_per_unit("url"), 600)
        self.assertGreater(g.tool_container_envelope("katana"), 0)
        self.assertGreater(g.envelope("agent_session_envelope_bytes"), 0)

    def test_envelope_zero_profile_falls_back(self):
        import json
        import tempfile
        # A measured 0 (bad/rounded-to-zero) must NOT be used verbatim.
        prof = {"agent_session_envelope_bytes": 0}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(prof, fh)
            path = fh.name
        try:
            os.environ["RESOURCE_PROFILE_PATH"] = path
            g.reset_profile_cache()
            self.assertGreater(g.envelope("agent_session_envelope_bytes"), 0)
        finally:
            os.unlink(path)

    def test_measured_overrides_fallback(self):
        import json
        import tempfile
        prof = {"bytes_per_unit": {"url": 375}, "agent_session_envelope_bytes": 999}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(prof, fh)
            path = fh.name
        try:
            os.environ["RESOURCE_PROFILE_PATH"] = path
            g.reset_profile_cache()
            self.assertEqual(g.bytes_per_unit("url"), 375)          # overridden
            self.assertEqual(g.bytes_per_unit("js_file"), 65536)    # fallback kept
            self.assertEqual(g.envelope("agent_session_envelope_bytes"), 999)
        finally:
            os.unlink(path)


class TestParseSize(GovernorTestBase):
    def test_suffixes(self):
        self.assertEqual(g.parse_size("2g"), 2 * GB)
        self.assertEqual(g.parse_size("512m"), 512 * 1024 * 1024)
        self.assertEqual(g.parse_size("1024k"), 1024 * 1024)
        self.assertEqual(g.parse_size("123"), 123)

    def test_b_suffix_and_case(self):
        self.assertEqual(g.parse_size("512MB"), 512 * 1024 * 1024)
        self.assertEqual(g.parse_size(" 2G "), 2 * GB)

    def test_invalid(self):
        self.assertIsNone(g.parse_size(""))
        self.assertIsNone(g.parse_size(None))
        self.assertIsNone(g.parse_size("abc"))
        self.assertIsNone(g.parse_size("-5g"))

    def test_env_bytes(self):
        os.environ["SOME_MEM"] = "3g"
        self.assertEqual(g.env_bytes("SOME_MEM", 1 * GB), 3 * GB)
        os.environ.pop("SOME_MEM", None)
        self.assertEqual(g.env_bytes("SOME_MEM", 1 * GB), 1 * GB)
        os.environ["SOME_MEM"] = ""
        self.assertEqual(g.env_bytes("SOME_MEM", 1 * GB), 1 * GB)
        os.environ.pop("SOME_MEM", None)


class TestCapLogging(GovernorTestBase):
    def test_scaled_logged_emits_only_on_reduce(self):
        g.set_mem_override(32 * GB, 2 * GB)  # scale 0.15 -> reduces
        buf = io.StringIO()
        with redirect_stdout(buf):
            out = g.scaled_logged(8, 1, "katana", "KATANA_PARALLELISM")
        self.assertEqual(out, 1)
        self.assertIn(g.RESOURCE_CAP_MARKER, buf.getvalue())
        self.assertIn("KATANA_PARALLELISM", buf.getvalue())

    def test_scaled_logged_silent_when_ample(self):
        g.set_mem_override(32 * GB, 32 * GB)  # scale 1.0 -> no reduction
        buf = io.StringIO()
        with redirect_stdout(buf):
            out = g.scaled_logged(8, 1, "katana", "KATANA_PARALLELISM")
        self.assertEqual(out, 8)
        self.assertNotIn(g.RESOURCE_CAP_MARKER, buf.getvalue())

    def test_budget_logged_emits_on_cap(self):
        g.set_mem_override(32 * GB, 512 * 1024 * 1024)
        buf = io.StringIO()
        with redirect_stdout(buf):
            out = g.budget_logged(300000, 500, "katana", "KATANA_MAX_URLS", 1000, 0.10)
        self.assertLess(out, 300000)
        self.assertIn(g.RESOURCE_CAP_MARKER, buf.getvalue())
        self.assertIn("KATANA_MAX_URLS", buf.getvalue())

    def test_budget_logged_silent_when_fits(self):
        g.set_mem_override(64 * GB, 40 * GB)
        buf = io.StringIO()
        with redirect_stdout(buf):
            out = g.budget_logged(300000, 500, "katana", "KATANA_MAX_URLS", 1000, 0.10)
        self.assertEqual(out, 300000)
        self.assertNotIn(g.RESOURCE_CAP_MARKER, buf.getvalue())


if __name__ == "__main__":
    unittest.main()
