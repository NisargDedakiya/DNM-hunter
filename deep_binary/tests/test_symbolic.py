"""Tests for angr-based deep binary analysis.

Compiles real targets and lets angr solve them. Skips gracefully if angr or gcc
is unavailable (angr is a heavy optional dependency).
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from deep_binary import HAVE_ANGR, find_control_hijack, reach_target

_HAVE_GCC = bool(shutil.which("gcc"))

_LICENSE = r'''
#include <stdio.h>
#include <unistd.h>
void authenticated(){ puts("ACCESS GRANTED"); }
int main(){ char b[32]; read(0,b,31);
  if(b[0]=='S'&&b[1]=='3'&&b[2]=='C'&&b[3]=='R'&&b[4]=='3'&&b[5]=='T') authenticated();
  else puts("denied"); return 0; }
'''
_OVERFLOW = '#include <stdio.h>\nint main(){char b[16]; gets(b); return 0;}\n'


@unittest.skipUnless(HAVE_ANGR and _HAVE_GCC, "angr/gcc not available")
class TestSymbolic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        lic_c = Path(cls.d) / "lic.c"; lic_c.write_text(_LICENSE)
        of_c = Path(cls.d) / "of.c"; of_c.write_text(_OVERFLOW)
        cls.lic = str(Path(cls.d) / "lic")
        cls.of = str(Path(cls.d) / "of")
        subprocess.run(["gcc", "-no-pie", "-fno-stack-protector", "-w", "-o", cls.lic, str(lic_c)], check=True)
        subprocess.run(["gcc", "-no-pie", "-fno-stack-protector", "-z", "execstack", "-w", "-o", cls.of, str(of_c)],
                       check=True, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def test_reach_target_solves_the_input(self):
        r = reach_target(self.lic, "authenticated", timeout_s=90)
        self.assertTrue(r.reached)
        self.assertIsNotNone(r.stdin)
        self.assertTrue(r.stdin.startswith(b"S3CR3T"))

    def test_reach_unknown_symbol_is_reported(self):
        r = reach_target(self.lic, "nonexistent_fn", timeout_s=10)
        self.assertFalse(r.reached)
        self.assertIn("not found", r.reason)

    def test_control_flow_hijack_detected(self):
        h = find_control_hijack(self.of, timeout_s=90)
        self.assertTrue(h.hijackable)
        self.assertIsNotNone(h.overflow_len)


class TestGraceful(unittest.TestCase):
    def test_module_imports_and_reports_availability(self):
        # HAVE_ANGR is a bool regardless of whether angr is installed.
        self.assertIn(HAVE_ANGR, (True, False))


if __name__ == "__main__":
    unittest.main()
