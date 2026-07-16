"""Tests for the web-application source SAST (code_audit).

Run: python -m unittest code_audit.tests.test_code_audit -v
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from code_audit import scan_code, scan_tree


def rules(findings):
    return {f.rule_id for f in findings}


_VULN_PY = '''
import os, subprocess, hashlib, pickle, random, yaml, requests
from flask import request, redirect, render_template_string

def handler():
    name = request.args.get("name")
    q = "SELECT * FROM users WHERE name = '" + name + "'"
    cursor.execute(q)                                  # SQLi
    os.system("ping " + name)                          # command injection
    eval(request.form["expr"])                         # RCE
    open("/data/" + name)                              # LFI / path traversal
    render_template_string("Hello " + name)            # SSTI
    requests.get(request.args.get("url"))              # SSRF
    redirect(request.args.get("next"))                 # open redirect
    hashlib.md5(pw).hexdigest()                        # weak hash
    pickle.loads(blob)                                 # insecure deserialization
    token = random.randint(0, 999999)                  # insecure RNG
    yaml.load(untrusted)                               # unsafe yaml load
'''

_SAFE_PY = '''
import hashlib
from flask import request

def handler():
    # parameterised query — must NOT be flagged as SQLi
    cursor.execute("SELECT * FROM users WHERE name = %s", (request.args.get("name"),))
    hashlib.sha256(b"data").hexdigest()   # strong hash, no finding
    open("/etc/config.json")              # constant path, not user-controlled
'''

_VULN_JS = '''
const express = require("express");
app.get("/x", (req, res) => {
  const name = req.query.name;
  db.query("SELECT * FROM u WHERE n = '" + name + "'");   // SQLi
  child_process.exec("ls " + name);                        // command injection
  res.send("<h1>" + name + "</h1>");                       // XSS
  document.write(req.query.html);                          // XSS
  const t = Math.random();                                 // insecure RNG
  localStorage.setItem("auth_token", jwt);                 // web storage token
});
'''


class TestDetection(unittest.TestCase):
    def test_python_top_classes(self):
        got = rules(scan_code(_VULN_PY, "app.py"))
        for r in ("CA-SQLI", "CA-CMDI", "CA-EVAL", "CA-LFI", "CA-SSTI",
                  "CA-SSRF", "CA-REDIR", "CA-HASH", "CA-DESERIAL", "CA-RANDOM"):
            self.assertIn(r, got, f"{r} should be detected in the vulnerable Python")

    def test_js_classes(self):
        got = rules(scan_code(_VULN_JS, "app.js"))
        for r in ("CA-SQLI", "CA-CMDI", "CA-XSS", "CA-RANDOM", "CA-WEBSTORE"):
            self.assertIn(r, got, f"{r} should be detected in the vulnerable JS")

    def test_findings_carry_vrt_and_cwe(self):
        f = [x for x in scan_code(_VULN_PY, "app.py") if x.rule_id == "CA-SQLI"][0]
        self.assertEqual(f.vrt, "server_side_injection.sql_injection")
        self.assertEqual(f.cwe, "CWE-89")
        self.assertEqual(f.severity, "critical")


class TestPrecision(unittest.TestCase):
    def test_parameterised_query_not_flagged(self):
        self.assertNotIn("CA-SQLI", rules(scan_code(_SAFE_PY, "safe.py")))

    def test_strong_hash_not_flagged(self):
        self.assertNotIn("CA-HASH", rules(scan_code(_SAFE_PY, "safe.py")))

    def test_constant_file_open_not_lfi(self):
        self.assertNotIn("CA-LFI", rules(scan_code(_SAFE_PY, "safe.py")))

    def test_constant_eval_arg_not_flagged(self):
        # eval on a literal is not RCE from untrusted input
        self.assertNotIn("CA-EVAL", rules(scan_code('x = eval("2 + 2")\n', "a.py")))


class TestTree(unittest.TestCase):
    def test_scan_tree_skips_vendor(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "app.py").write_text(_VULN_PY)
            (Path(d) / "node_modules").mkdir()
            (Path(d) / "node_modules" / "x.py").write_text(_VULN_PY)
            found = scan_tree(d)
            self.assertTrue(found)
            self.assertFalse(any("node_modules" in f.file for f in found))


if __name__ == "__main__":
    unittest.main()
