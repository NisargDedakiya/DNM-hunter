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
  const sessionToken = Math.random().toString(36);         // insecure RNG (security use)
  localStorage.setItem("auth_token", jwt);                 // web storage token
});
'''

# JWT / IDOR / file-upload / CORS — the classes added to raise finding quality.
_VULN_AUTH_PY = '''
import jwt
from flask import request

JWT_SECRET = "hardcoded-signing-secret"          # hard-coded secret

def login(token):
    jwt.decode(token, verify=False)              # signature verification disabled
    jwt.decode(token, algorithms=["none"])       # 'none' algorithm accepted
    jwt.encode(payload, "hardcoded-signing-secret")  # hard-coded secret

def get_record():
    uid = request.args.get("id")
    return Invoice.objects.get(id=uid)           # IDOR (heuristic)

def upload():
    f = request.files["file"]
    f.save("/uploads/" + request.form["name"])   # unrestricted file upload
'''

_VULN_CORS_JS = '''
app.use((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin);  // reflected origin
});
const opts = { origin: true, credentials: true };                    // wildcard + creds
'''

# CSRF / default creds / GraphQL / PRNG seed / static IV / token-in-URL / CSV.
_VULN_MISC_PY = '''
import csv, random
from flask import request

DB_PASSWORD = "changeme"                     # default credential
random.seed(42)                              # predictable PRNG seed
iv = b"0000000000000000"                     # static IV
graphql = {"introspection": True}            # introspection enabled

@csrf_exempt
def export():                                # CSRF protection disabled
    name = request.args.get("name")
    w = csv.writer(fh)
    w.writerow([name, "x"])                  # CSV injection (tainted)
    url = "https://api/cb?access_token=" + tok  # token in URL
    return url
'''

# Clean file — none of the new rules should fire (guards against false positives).
_SAFE_MISC_PY = '''
import csv, os
from django.views.decorators.csrf import csrf_exempt   # import only, no decorator

password = os.environ["DB_PASSWORD"]         # from env, not hardcoded
iv = os.urandom(16)                          # random IV
config = {"introspection": False}            # disabled
w = csv.writer(fh)
w.writerow(["static", "header"])             # constant row, not tainted
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


class TestAuthAndAccessControl(unittest.TestCase):
    def test_jwt_idor_upload_classes(self):
        got = rules(scan_code(_VULN_AUTH_PY, "auth.py"))
        for r in ("CA-JWT-NOVERIFY", "CA-JWT-NONE", "CA-JWT-SECRET",
                  "CA-IDOR", "CA-UPLOAD"):
            self.assertIn(r, got, f"{r} should be detected in the vulnerable auth code")

    def test_cors_class(self):
        self.assertIn("CA-CORS", rules(scan_code(_VULN_CORS_JS, "cors.js")))

    def test_upload_matches_indexed_files_save(self):
        # request.files["f"].save(...) — .save after `]`, must still match.
        code = 'from flask import request\nrequest.files["f"].save("/up/" + request.form["n"])\n'
        self.assertIn("CA-UPLOAD", rules(scan_code(code, "up.py")))

    def test_jwt_verify_false_not_mislabelled_as_tls(self):
        # jwt.decode(t, verify=False) is a JWT bypass, NOT a TLS-verify issue.
        got = rules(scan_code('import jwt\njwt.decode(tok, verify=False)\n', "j.py"))
        self.assertIn("CA-JWT-NOVERIFY", got)
        self.assertNotIn("CA-TLSVERIFY", got)


class TestMiscMisconfigClasses(unittest.TestCase):
    def test_new_classes_detected(self):
        got = rules(scan_code(_VULN_MISC_PY, "misc.py"))
        for r in ("CA-DEFAULTCRED", "CA-SEED", "CA-IV", "CA-GRAPHQL",
                  "CA-CSRF", "CA-CSV", "CA-TOKENURL"):
            self.assertIn(r, got, f"{r} should be detected in the vulnerable misc code")

    def test_csrf_disabled_is_firm(self):
        f = [x for x in scan_code(_VULN_MISC_PY, "misc.py") if x.rule_id == "CA-CSRF"][0]
        self.assertEqual(f.confidence, "firm")

    def test_csv_injection_needs_taint(self):
        f = [x for x in scan_code(_VULN_MISC_PY, "misc.py") if x.rule_id == "CA-CSV"][0]
        self.assertEqual(f.confidence, "firm")

    def test_no_false_positives_on_safe_misc(self):
        got = rules(scan_code(_SAFE_MISC_PY, "safe_misc.py"))
        for r in ("CA-DEFAULTCRED", "CA-IV", "CA-GRAPHQL", "CA-CSRF", "CA-CSV"):
            self.assertNotIn(r, got, f"{r} must NOT fire on the safe file")


class TestOwaspApiClasses(unittest.TestCase):
    """NoSQL injection, mass assignment/BOPLA, plaintext password, exposed docs."""

    _VULN_JS = '''
app.get("/u", (req, res) => {
  db.collection("u").find({ name: req.query.name });   // NoSQL operator injection
  db.eval("$where: this.x == '" + req.query.x + "'");  // $where server-side JS
  const user = new User(req.body);                      // mass assignment
  Object.assign(profile, req.body);                     // mass assignment
});
app.use("/api-docs", require("swagger-ui-express").serve);  // exposed swagger
'''
    _VULN_PY = '''
from flask import request
def register():
    user.password = request.form["pw"]     # plaintext password store
    if password == request.form["pw"]:     # plaintext compare
        pass
    User(**request.json)                    # mass assignment
'''
    _SAFE_JS = '''
db.collection("u").find({ name: "constant" });     // constant, safe
const arr = [1,2,3].find(x => x === userId);        // Array.find, not Mongo
const user = new User({ id: 1, name: "bob" });      // literal, not req.body
'''
    _SAFE_PY = '''
import bcrypt
from flask import request
user.password = bcrypt.hashpw(request.form["pw"].encode(), bcrypt.gensalt())
'''

    def test_nosql_and_massassign_and_swagger(self):
        got = rules(scan_code(self._VULN_JS, "api.js"))
        for r in ("CA-NOSQL", "CA-MASSASSIGN", "CA-SWAGGER"):
            self.assertIn(r, got, f"{r} should fire on the vulnerable JS")

    def test_plaintext_password_and_kwargs_massassign(self):
        got = rules(scan_code(self._VULN_PY, "api.py"))
        self.assertIn("CA-PLAINTEXTPW", got)
        self.assertIn("CA-MASSASSIGN", got)

    def test_no_false_positives(self):
        js = rules(scan_code(self._SAFE_JS, "safe_api.js"))
        for r in ("CA-NOSQL", "CA-MASSASSIGN"):
            self.assertNotIn(r, js, f"{r} must not fire on safe JS")
        py = rules(scan_code(self._SAFE_PY, "safe_api.py"))
        self.assertNotIn("CA-PLAINTEXTPW", py)

    def test_jwt_none_is_high_severity(self):
        f = [x for x in scan_code(_VULN_AUTH_PY, "auth.py") if x.rule_id == "CA-JWT-NONE"][0]
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.cwe, "CWE-347")


class TestConfidence(unittest.TestCase):
    def test_every_finding_has_confidence(self):
        for f in scan_code(_VULN_PY, "app.py"):
            self.assertIn(f.confidence, ("firm", "tentative", "heuristic"))

    def test_confidence_survives_to_dict(self):
        f = scan_code(_VULN_PY, "app.py")[0]
        self.assertIn("confidence", f.to_dict())

    def test_tainted_sink_is_firm(self):
        # user input provably reaching a SQL sink → firm
        f = [x for x in scan_code(_VULN_PY, "app.py") if x.rule_id == "CA-SQLI"][0]
        self.assertEqual(f.confidence, "firm")

    def test_idor_is_heuristic(self):
        f = [x for x in scan_code(_VULN_AUTH_PY, "auth.py") if x.rule_id == "CA-IDOR"][0]
        self.assertEqual(f.confidence, "heuristic")

    def test_jwt_none_is_firm(self):
        f = [x for x in scan_code(_VULN_AUTH_PY, "auth.py") if x.rule_id == "CA-JWT-NONE"][0]
        self.assertEqual(f.confidence, "firm")

    def test_hardcoded_secret_is_tentative(self):
        f = [x for x in scan_code(_VULN_AUTH_PY, "auth.py") if x.rule_id == "CA-JWT-SECRET"][0]
        self.assertEqual(f.confidence, "tentative")


_VULN_PHP = '''<?php
$id = $_GET["id"];
$q = "SELECT * FROM users WHERE id = " . $id;
mysqli_query($conn, $q);                       // SQLi (concat-built query)
echo $_GET["name"];                            // reflected XSS
system("ping " . $_GET["host"]);               // command injection
include $_GET["page"] . ".php";                // LFI / path traversal
$data = file_get_contents($_GET["url"]);       // SSRF
eval($_POST["code"]);                          // RCE
'''

_SAFE_PHP = '''<?php
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");   // parameterised
$stmt->bind_param("i", $_GET["id"]);
echo htmlspecialchars($_GET["name"]);          // output-encoded — safe
echo "static content";                         // constant
include "config.php";                          // constant path
$n = intval($_GET["n"]);                       // cast — safe
'''


class TestPhp(unittest.TestCase):
    def test_php_injection_classes(self):
        got = rules(scan_code(_VULN_PHP, "app.php"))
        for r in ("CA-SQLI", "CA-XSS", "CA-CMDI", "CA-LFI", "CA-SSRF", "CA-EVAL"):
            self.assertIn(r, got, f"{r} should be detected in the vulnerable PHP")

    def test_php_sqli_is_critical_firm(self):
        f = [x for x in scan_code(_VULN_PHP, "app.php") if x.rule_id == "CA-SQLI"][0]
        self.assertEqual(f.severity, "critical")
        self.assertEqual(f.confidence, "firm")

    def test_php_safe_file_is_clean(self):
        got = rules(scan_code(_SAFE_PHP, "safe.php"))
        for r in ("CA-SQLI", "CA-XSS", "CA-LFI", "CA-CMDI"):
            self.assertNotIn(r, got, f"{r} must NOT fire on the safe PHP (parameterised/encoded)")

    def test_php_files_are_scanned_by_tree(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "index.php").write_text(_VULN_PHP)
            found = scan_tree(d)
            self.assertTrue(any(f.file.endswith(".php") for f in found))


# A file mirroring the practical-14 pattern that produced 6 false/mislabelled
# XSS findings: a constant $message, DB values echoed, and a tainted var name
# ($id, $username) that collides with array-key/string-literal substrings.
_PHP_XSS_QUALITY = '''<?php
$id = intval($_GET["delete"]);
$username = sanitize($_POST["username"]);
$message = "Invalid username or password";
$stmt = $pdo->query("SELECT * FROM users");
$users = $stmt->fetchAll();
echo $_GET["q"];                                   // reflected — request, unsanitised
echo sanitize($_POST["name"]);                     // custom sanitiser — safe
echo $message;                                     // constant — NOT xss
foreach ($users as $user):
  echo $user["id"];                                // stored (db) — id key collides with $id
  echo $user["username"];                          // stored (db) — real candidate
endforeach;
echo $_SESSION["username"];                        // stored (session)
?>
<input value="<?php echo $user["email"]; ?>">
<a href="?id=<?php echo $user["id"]; ?>">x</a>
'''


class TestPhpXssQuality(unittest.TestCase):
    def _by_line(self, sanitizers=None):
        from code_audit.scanner import collect_php_sanitizers
        s = sanitizers if sanitizers is not None else collect_php_sanitizers([_PHP_XSS_QUALITY])
        return {f.line: f for f in scan_code(_PHP_XSS_QUALITY, "app.php", s)}

    def test_constant_message_is_not_flagged(self):
        # the $message constant collides with the word "username" inside the
        # literal, but is NOT user input → must not be an XSS finding
        self.assertNotIn(9, self._by_line())

    def test_reflected_request_is_high_firm(self):
        f = self._by_line()[7]
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.confidence, "firm")
        self.assertEqual(f.vrt, "cross_site_scripting.reflected")

    def test_custom_sanitizer_recognised(self):
        # sanitize() is defined in another file (functions.php); simulate the
        # cross-file collection scan_tree does by passing it in explicitly.
        self.assertNotIn(8, self._by_line(sanitizers={"sanitize"}))

    def test_db_value_is_potential_stored_low(self):
        f = self._by_line()[12]                # echo $user["username"]
        self.assertEqual(f.severity, "low")
        self.assertEqual(f.confidence, "heuristic")
        self.assertEqual(f.vrt, "cross_site_scripting.stored")
        self.assertIn("stored", f.title.lower())

    def test_session_value_is_stored_medium(self):
        f = self._by_line()[14]                # echo $_SESSION["username"]
        self.assertEqual(f.severity, "medium")
        self.assertEqual(f.confidence, "tentative")

    def test_attribute_and_url_contexts_detected(self):
        by = self._by_line()
        self.assertIn("attribute context", by[16].detail)   # value="..."
        self.assertIn("URL context", by[17].detail)         # href="?id=..."

    def test_reflected_and_stored_are_distinct_types(self):
        vrts = {f.vrt for f in self._by_line().values()}
        self.assertIn("cross_site_scripting.reflected", vrts)
        self.assertIn("cross_site_scripting.stored", vrts)


# The portfolio-website false-positive pattern: Math.random() for animation.
_ANIM_JS = '''
class Particle {
  constructor() {
    this.x = Math.random() * width;
    this.y = Math.random() * height;
    this.vx = (Math.random() - 0.5) * 0.4;
    this.radius = Math.random() * 1.5 + 1;
    this.color = Math.random() > 0.3 ? "blue" : "red";
  }
}
const key = Math.random();                       // React key-ish, not security
setPing(prev + Math.floor(Math.random() * 7) - 3);
'''

_RNG_SECURITY_JS = '''
const sessionToken = Math.random().toString(36).slice(2);
this.csrfToken = Math.random();
let apiKey = Math.random().toString(16);
const r = Math.random();
const resetToken = "reset-" + r;                 // rng flows into a token
const speed = Math.random() * 5;                 // NOT security
'''


class TestInsecureRngContext(unittest.TestCase):
    def test_animation_random_is_not_flagged(self):
        # the exact portfolio-website case: particle/animation Math.random()
        self.assertNotIn("CA-RANDOM", rules(scan_code(_ANIM_JS, "NetworkMesh.tsx")))

    def test_react_key_and_ping_not_flagged(self):
        got = [f for f in scan_code(_ANIM_JS, "Hud.tsx") if f.rule_id == "CA-RANDOM"]
        self.assertEqual(got, [])

    def test_security_token_is_flagged(self):
        got = {f.line for f in scan_code(_RNG_SECURITY_JS, "auth.ts") if f.rule_id == "CA-RANDOM"}
        self.assertIn(2, got)   # sessionToken = Math.random().toString(36)
        self.assertIn(3, got)   # this.csrfToken = Math.random()
        self.assertIn(4, got)   # apiKey = Math.random().toString(16)

    def test_rng_flow_into_token_is_flagged(self):
        got = {f.line for f in scan_code(_RNG_SECURITY_JS, "auth.ts") if f.rule_id == "CA-RANDOM"}
        self.assertIn(6, got)   # resetToken = "reset-" + r  (r came from Math.random)

    def test_non_security_rng_not_flagged(self):
        got = {f.line for f in scan_code(_RNG_SECURITY_JS, "auth.ts") if f.rule_id == "CA-RANDOM"}
        self.assertNotIn(7, got)   # const speed = Math.random() * 5

    def test_python_token_randint_still_flagged(self):
        code = 'token = random.randint(0, 999999)\n'
        self.assertIn("CA-RANDOM", rules(scan_code(code, "a.py")))

    def test_python_non_security_random_not_flagged(self):
        code = 'jitter = random.random() * 0.1\n'
        self.assertNotIn("CA-RANDOM", rules(scan_code(code, "a.py")))


_MAIL_ROUTE = '''import nodemailer from "nodemailer";
export async function POST(request) {
  const { name, email, subject, message } = await request.json();
  const transporter = nodemailer.createTransport({});
  const mailOptions = {
    from: `"${name}" <me@example.com>`,
    to: "me@example.com",
    replyTo: email,
    subject: `[Portfolio] ${subject}`,
    html: `<strong>${name}</strong><p>${message}</p>`,
  };
  console.log(`Message from Name: ${name}, Subject: ${subject}`);
  await transporter.sendMail(mailOptions);
}
'''


class TestDestructuringTaint(unittest.TestCase):
    def test_destructured_request_value_is_tainted(self):
        code = ('export async function POST(req){\n'
                '  const { id } = await req.json();\n'
                '  db.query("SELECT * FROM u WHERE id = " + id);\n}\n')
        self.assertIn("CA-SQLI", rules(scan_code(code, "route.ts")))

    def test_destructured_into_innerhtml(self):
        code = ('const { html } = req.body;\n'
                'el.innerHTML = html;\n')
        self.assertIn("CA-XSS", rules(scan_code(code, "a.ts")))


class TestEmailInjection(unittest.TestCase):
    def _by_rule(self, code, file="route.ts"):
        return {f.rule_id: f for f in scan_code(code, file)}

    def test_email_header_injection_flagged(self):
        f = self._by_rule(_MAIL_ROUTE).get("CA-EMAILHDR")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "low")
        self.assertEqual(f.line, 6)   # the `from:` field, not the console.log

    def test_email_html_injection_flagged(self):
        f = self._by_rule(_MAIL_ROUTE).get("CA-EMAILXSS")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "low")
        self.assertEqual(f.vrt, "cross_site_scripting.stored")

    def test_log_line_is_not_a_mail_header(self):
        # the console.log contains "Subject:" text but is not a header field
        f = self._by_rule(_MAIL_ROUTE).get("CA-EMAILHDR")
        self.assertNotEqual(f.line, 12)

    def test_no_email_findings_without_mail_context(self):
        # same shape, but no mail library → not an email sink (avoids FPs on
        # ordinary objects / React that happen to use from:/to:/html:)
        code = ('const { name, message } = await request.json();\n'
                'const o = { from: name, html: `<p>${message}</p>` };\n')
        got = rules(scan_code(code, "x.ts"))
        self.assertNotIn("CA-EMAILHDR", got)
        self.assertNotIn("CA-EMAILXSS", got)

    def test_constant_mail_fields_are_clean(self):
        code = ('import nodemailer from "x";\n'
                'const o = { from: "a@b.com", html: "<p>static</p>" };\n'
                'transporter.sendMail(o);\n')
        got = rules(scan_code(code, "x.ts"))
        self.assertNotIn("CA-EMAILHDR", got)
        self.assertNotIn("CA-EMAILXSS", got)


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
