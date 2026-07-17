"""Tests for OS host-config + native-code (low-level) vulnerability detection.

Run: python -m unittest os_audit.tests.test_os_audit -v
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from os_audit import audit_tree
from os_audit.host_config import audit_fstab, audit_passwd, audit_shadow, audit_sshd_config, audit_sudoers, audit_sysctl
from os_audit.native_code import scan_c_source


def rids(findings):
    return {f.rule_id for f in findings}


class TestHostConfig(unittest.TestCase):
    def test_sshd_root_login_and_empty_pw(self):
        got = rids(audit_sshd_config("PermitRootLogin yes\nPermitEmptyPasswords yes\n", "sshd_config"))
        self.assertIn("OS-SSH-001", got)
        self.assertIn("OS-SSH-002", got)

    def test_sshd_hardened_is_clean(self):
        got = audit_sshd_config("PermitRootLogin no\nPasswordAuthentication no\nProtocol 2\n", "sshd_config")
        self.assertEqual(got, [])

    def test_sudoers_nopasswd(self):
        self.assertIn("OS-SUDO-001", rids(audit_sudoers("deploy ALL=(ALL) NOPASSWD: ALL\n", "sudoers")))

    def test_sysctl_aslr_disabled_is_critical(self):
        f = audit_sysctl("kernel.randomize_va_space = 0\n", "sysctl.conf")
        self.assertTrue(any(x.severity == "critical" for x in f))

    def test_sysctl_aslr_enabled_is_clean(self):
        self.assertEqual(audit_sysctl("kernel.randomize_va_space = 2\n", "sysctl.conf"), [])

    def test_passwd_uid0_backdoor(self):
        self.assertIn("OS-PASSWD-001", rids(audit_passwd("evil:x:0:0::/h:/bin/sh\n", "passwd")))

    def test_shadow_empty_hash(self):
        self.assertIn("OS-SHADOW-001", rids(audit_shadow("bob::19000:0:99999:7:::\n", "shadow")))

    def test_fstab_missing_hardening(self):
        self.assertIn("OS-FSTAB-001", rids(audit_fstab("tmpfs /tmp tmpfs defaults 0 0\n", "fstab")))


class TestNativeCode(unittest.TestCase):
    def test_gets_is_critical(self):
        f = scan_c_source("int main(){char b[8]; gets(b);}", "x.c")
        self.assertTrue(any(x.rule_id == "NATIVE-001" and x.severity == "critical" for x in f))

    def test_strcpy_and_sprintf(self):
        got = rids(scan_c_source('strcpy(a,b); sprintf(c,"%s",d);', "x.c"))
        self.assertIn("NATIVE-002", got)
        self.assertIn("NATIVE-004", got)

    def test_command_injection_variable_vs_literal(self):
        var = rids(scan_c_source("system(cmd);", "x.c"))
        lit = rids(scan_c_source('system("/bin/ls");', "x.c"))
        self.assertIn("NATIVE-007", var)      # variable arg -> injection
        self.assertIn("NATIVE-008", lit)      # literal -> low
        self.assertNotIn("NATIVE-007", lit)

    def test_format_string(self):
        self.assertIn("NATIVE-009", rids(scan_c_source("printf(user);", "x.c")))

    def test_safe_patterns_not_flagged(self):
        safe = 'snprintf(b, sizeof b, "%s", s); printf("%s", s); fgets(b, 64, stdin);'
        self.assertEqual(scan_c_source(safe, "x.c"), [])


class TestIntegration(unittest.TestCase):
    def test_audit_tree_combines_both(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "sshd_config").write_text("PermitRootLogin yes\n")
            (root / "vuln.c").write_text("int f(char*u){char b[8]; strcpy(b,u); gets(b);}")
            res = audit_tree(root)
            kinds = {f.kind for f in res.findings}
            self.assertIn("host-config", kinds)
            self.assertIn("native-code", kinds)
            self.assertEqual(res.summary["highestSeverity"], "critical")


if __name__ == "__main__":
    unittest.main()
