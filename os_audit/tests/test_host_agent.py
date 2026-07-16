"""Tests for the live-host collector agent (against a fake root tree)."""
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from os_audit.host_agent import collect_and_audit


def _rids(res):
    return {f.rule_id.split(":")[0] for f in res.findings}


class TestHostAgent(unittest.TestCase):
    def _fake_root(self, d: Path):
        (d / "etc" / "ssh").mkdir(parents=True)
        (d / "etc" / "ssh" / "sshd_config").write_text("PermitRootLogin yes\n")
        (d / "proc" / "sys" / "kernel").mkdir(parents=True)
        (d / "proc" / "sys" / "kernel" / "randomize_va_space").write_text("0\n")
        (d / "usr" / "bin").mkdir(parents=True)

    def test_live_config_and_sysctl(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t); self._fake_root(d)
            res = collect_and_audit(d, suid_dirs=["/usr/bin"], ww_dirs=["/etc"])
            got = _rids(res)
            self.assertIn("OS-SSH-001", got)          # root login from live sshd_config
            self.assertIn("LIVE-SYSCTL", got)          # ASLR disabled read from /proc/sys

    def test_gtfo_suid_binary_is_critical(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t); self._fake_root(d)
            evil = d / "usr" / "bin" / "bash"
            evil.write_text("#!x\n")
            os.chmod(evil, 0o755 | stat.S_ISUID)       # setuid bash -> GTFO privesc
            res = collect_and_audit(d, suid_dirs=["/usr/bin"], ww_dirs=["/etc"])
            crit = [f for f in res.findings if f.rule_id == "LIVE-SUID-GTFO"]
            self.assertTrue(crit and crit[0].severity == "critical")

    def test_standard_suid_not_flagged(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t); self._fake_root(d)
            std = d / "usr" / "bin" / "sudo"
            std.write_text("#!x\n")
            os.chmod(std, 0o755 | stat.S_ISUID)        # sudo is expected -> not flagged
            res = collect_and_audit(d, suid_dirs=["/usr/bin"], ww_dirs=["/etc"])
            self.assertFalse(any(f.path.endswith("/sudo") for f in res.findings))

    def test_world_writable_file_flagged(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t); self._fake_root(d)
            ww = d / "etc" / "app.conf"
            ww.write_text("x")
            os.chmod(ww, 0o666)
            res = collect_and_audit(d, suid_dirs=["/usr/bin"], ww_dirs=["/etc"])
            self.assertIn("LIVE-WWRITE", _rids(res))


if __name__ == "__main__":
    unittest.main()
