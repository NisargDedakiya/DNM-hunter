"""Tests for the ELF hardening analyzer — compiles real binaries with gcc.

Skips gracefully if gcc/readelf are unavailable.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from binary_audit import analyze_elf

_SRC = ('#include <stdio.h>\n#include <string.h>\n#include <stdlib.h>\n'
        'int main(int c,char**v){char b[64];strcpy(b,v[1]);gets(b);system(b);return 0;}\n')

_HAVE_GCC = shutil.which("gcc") and shutil.which("readelf")


@unittest.skipUnless(_HAVE_GCC, "gcc/readelf not available")
class TestElfHardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        src = Path(cls.d) / "t.c"
        src.write_text(_SRC)
        cls.vuln = str(Path(cls.d) / "vuln")
        cls.hard = str(Path(cls.d) / "hard")
        subprocess.run(["gcc", "-fno-stack-protector", "-no-pie", "-z", "execstack",
                        "-z", "norelro", "-w", "-o", cls.vuln, str(src)], check=True)
        subprocess.run(["gcc", "-fstack-protector-all", "-fPIE", "-pie",
                        "-Wl,-z,relro,-z,now", "-D_FORTIFY_SOURCE=2", "-O2", "-w",
                        "-o", cls.hard, str(src)], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def test_insecure_binary_flags_all_protections(self):
        r = analyze_elf(self.vuln)
        self.assertTrue(r.is_elf)
        self.assertFalse(r.properties["nx"])
        self.assertFalse(r.properties["pie"])
        self.assertEqual(r.properties["relro"], "none")
        self.assertFalse(r.properties["canary"])
        rids = {f.rule_id for f in r.findings}
        self.assertIn("BIN-NX", rids)
        self.assertIn("BIN-CANARY", rids)
        self.assertIn("BIN-IMPORT-gets", rids)

    def test_hardened_binary_has_protections(self):
        r = analyze_elf(self.hard)
        self.assertTrue(r.properties["nx"])
        self.assertTrue(r.properties["pie"])
        self.assertEqual(r.properties["relro"], "full")
        self.assertTrue(r.properties["canary"])
        rids = {f.rule_id for f in r.findings}
        # no hardening findings on a hardened build...
        self.assertNotIn("BIN-NX", rids)
        self.assertNotIn("BIN-CANARY", rids)
        # ...but the inherent dangerous import is still reported
        self.assertIn("BIN-IMPORT-gets", rids)

    def test_non_elf_is_reported(self):
        p = Path(self.d) / "notelf.txt"
        p.write_text("hello")
        r = analyze_elf(p)
        self.assertFalse(r.is_elf)


if __name__ == "__main__":
    unittest.main()
