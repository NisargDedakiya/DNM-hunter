"""vuln_kb — the vulnerability knowledge base.

A single machine-readable source of truth for every vulnerability class the
platform hunts. Each entry answers the questions a security analyst (human or AI)
needs before it can act:

    what it is · how to detect it · what evidence to collect · how to VERIFY it
    (which oracle) · CWE / OWASP-Web / OWASP-API / CAPEC / Bugcrowd-VRT ·
    default severity · impact · remediation · references · which DNM engine covers it

This is the connective tissue between the detectors (code_audit `CA-*`,
mobile_audit `MA-*`, llm_audit `LLM-*`), the verification oracles (`verify`), the
OWASP map (`vrt.owasp`) and the report generator. The AI agent reads it to know
*what to build and how to confirm it*; the reporter reads it to enrich a finding
with standards mappings and remediation.

CLI:  python -m vuln_kb [name|id] [--json]
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass

CRIT, HIGH, MED, LOW = "critical", "high", "medium", "low"

# Verification methods → the deterministic oracle that confirms them (see verify/).
# "manual"/"dynamic" mean no single-request oracle proves it (needs a session,
# multi-step flow, or human judgement).
VERIFY_TIMING = ("timing", "verify.TimingOracle — response time scales with an injected delay")
VERIFY_BOOLEAN = ("boolean", "verify.BooleanOracle — TRUE/FALSE conditions diverge")
VERIFY_REFLECTION = ("reflection", "verify.ReflectionOracle — a unique marker returns raw/unencoded")
VERIFY_OAST = ("oast", "verify.OastOracle — the server makes an out-of-band callback")
VERIFY_DIFFERENTIAL = ("differential", "verify.DifferentialOracle — an unauthorised identity gets protected data")
VERIFY_STATIC = ("static", "confirmed from source by a detector rule; no live oracle")
VERIFY_MANUAL = ("manual", "needs a session / multi-step flow / human judgement — no single-request oracle")


@dataclass
class Verify:
    method: str      # timing | boolean | reflection | oast | differential | static | manual
    how: str         # the yes/no question the verifier answers, and with what

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Vuln:
    id: str
    name: str
    category: str            # Bugcrowd-style family
    severity: str            # default/typical severity
    cwe: str
    owasp_web: str           # A01..A10 (2021), or ""
    owasp_api: str           # API1..API10 (2023), or ""
    capec: str               # CAPEC-nn, or ""
    vrt: str                 # canonical Bugcrowd VRT id
    description: str
    impact: str
    where: list[str]         # injection points / where to look
    payloads: list[str]      # representative probes
    evidence: list[str]      # what to collect as proof
    verify: Verify           # how the platform confirms exploitability
    remediation: str
    references: list[str]
    engines: list[str]       # DNM detectors/engines that cover it
    static_confidence: str   # firm | tentative | heuristic | dynamic-only

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


_REF = {
    "owasp_web": "https://owasp.org/Top10/",
    "owasp_api": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
    "cwe": "https://cwe.mitre.org/",
    "wstg": "https://owasp.org/www-project-web-security-testing-guide/",
}


KB: list[Vuln] = [
    Vuln("sqli", "SQL Injection", "Server-Side Injection", CRIT, "CWE-89", "A03", "API8", "CAPEC-66",
         "server_side_injection.sql_injection",
         "User input alters the structure of a SQL query executed by the backend.",
         "Read/modify/delete arbitrary database rows, auth bypass, sometimes RCE via stacked queries.",
         ["URL query params", "POST body", "JSON fields", "cookies", "HTTP headers"],
         ["'", "1' OR '1'='1", "1 AND SLEEP(5)", "1' UNION SELECT NULL-- -", "1'; WAITFOR DELAY '0:0:5'-- -"],
         ["SQL error message", "measured time delay under SLEEP()", "boolean page divergence", "extracted rows"],
         Verify(*VERIFY_TIMING),
         "Use parameterised queries / prepared statements; never concatenate input into SQL; least-privilege DB user.",
         [_REF["owasp_web"], _REF["cwe"] + "definitions/89.html", _REF["wstg"]],
         ["code_audit CA-SQLI", "code_audit CA-SQLI (PHP)", "mobile_audit MA-SQLI", "web_attack timing/boolean oracle"],
         "firm"),

    Vuln("nosqli", "NoSQL Injection", "Server-Side Injection", HIGH, "CWE-943", "A03", "API8", "CAPEC-676",
         "server_side_injection.nosql_injection",
         "User input alters a NoSQL query — operator injection ({\"$gt\":\"\"}) or server-side JS ($where).",
         "Auth bypass, data exfiltration, on Mongo $where potential code execution.",
         ["JSON body fields", "query params parsed into query objects"],
         ["{\"$gt\":\"\"}", "{\"$ne\":null}", "';return true;var x='", "$where: '1==1'"],
         ["auth bypass with an operator object", "boolean divergence", "$where evaluation"],
         Verify(*VERIFY_BOOLEAN),
         "Cast/validate input types; reject query operators from user input; use an ODM with strict schemas.",
         [_REF["owasp_web"], _REF["cwe"] + "definitions/943.html"],
         ["code_audit CA-NOSQL"], "tentative"),

    Vuln("xss", "Cross-Site Scripting", "Cross-Site Scripting", HIGH, "CWE-79", "A03", "API8", "CAPEC-63",
         "cross_site_scripting.reflected",
         "Untrusted input is reflected/stored into a page and executes as script in the victim's browser.",
         "Session/cookie theft, account takeover, keylogging, defacement, wormable stored payloads.",
         ["search fields", "forms", "comments", "URL params", "headers reflected into pages"],
         ["<script>alert(1)</script>", "\"><svg/onload=alert(1)>", "<img src=x onerror=alert(1)>"],
         ["marker returned raw (not HTML-encoded)", "JS executed", "DOM modified", "cookie readable"],
         Verify(*VERIFY_REFLECTION),
         "Context-aware output encoding; a strict Content-Security-Policy; framework auto-escaping; sanitise stored HTML.",
         [_REF["owasp_web"], _REF["cwe"] + "definitions/79.html"],
         ["code_audit CA-XSS", "mobile_audit MA-WEBVIEW-JS", "web_attack reflection oracle"],
         "firm"),

    Vuln("idor", "Insecure Direct Object Reference", "Broken Access Control", HIGH, "CWE-639", "A01", "API1", "CAPEC-180",
         "broken_access_control.idor",
         "Changing an object identifier exposes or modifies another user's data because authorization is missing.",
         "Read/modify other users' records, mass data exposure, privilege escalation.",
         ["/api/user/{id}", "/invoice/{n}", "object ids in body/query", "GUIDs that are guessable/enumerable"],
         ["increment/decrement the id", "swap to another user's id", "enumerate sequential ids"],
         ["another user's data returned", "action succeeds as a non-owner", "no 401/403 for a foreign id"],
         Verify(*VERIFY_DIFFERENTIAL),
         "Enforce object-level authorization on every request (does THIS user own THIS object); use unguessable, scoped ids.",
         [_REF["owasp_api"], _REF["cwe"] + "definitions/639.html"],
         ["code_audit CA-IDOR (static lead)", "web_attack differential oracle (confirm)"],
         "heuristic"),

    Vuln("ssrf", "Server-Side Request Forgery", "Server-Side Injection", HIGH, "CWE-918", "A10", "API7", "CAPEC-664",
         "server_side_injection.ssrf",
         "The server can be made to send HTTP requests to attacker-chosen URLs, including internal/metadata hosts.",
         "Access internal services, cloud metadata (169.254.169.254) → credential theft, port scanning, RCE pivots.",
         ["url/uri/redirect/callback/webhook/image params", "XML/SVG/PDF fetchers", "import-from-URL features"],
         ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/", "http://<oast-domain>/"],
         ["out-of-band callback to attacker infra", "internal service response", "cloud metadata body", "DNS interaction"],
         Verify(*VERIFY_OAST),
         "Allow-list outbound hosts; resolve+validate the target IP (block private/link-local); disable unused URL schemes.",
         [_REF["owasp_web"], _REF["cwe"] + "definitions/918.html"],
         ["code_audit CA-SSRF", "mobile_audit (n/a)", "web_attack OAST oracle"],
         "firm"),

    Vuln("command_injection", "OS Command Injection", "Server-Side Injection", CRIT, "CWE-78", "A03", "API8", "CAPEC-88",
         "server_side_injection.rce",
         "User input reaches an OS shell, letting an attacker run arbitrary system commands.",
         "Full server compromise, data theft, lateral movement, persistence.",
         ["params passed to shell/exec", "filenames", "ping/host/dns lookup features"],
         ["; sleep 5", "| id", "$(whoami)", "`curl http://<oast>`"],
         ["measured delay under sleep", "command output reflected", "out-of-band callback"],
         Verify(*VERIFY_TIMING),
         "Never pass input to a shell; use exec APIs with an argument array; strict allow-list validation.",
         [_REF["owasp_web"], _REF["cwe"] + "definitions/78.html"],
         ["code_audit CA-CMDI", "mobile_audit (n/a)", "web_attack timing oracle"],
         "firm"),

    Vuln("xxe", "XML External Entity Injection", "Server-Side Injection", HIGH, "CWE-611", "A05", "API8", "CAPEC-201",
         "server_side_injection.xxe",
         "An XML parser resolves attacker-defined external entities, enabling file read and SSRF.",
         "Local file disclosure, SSRF, in some parsers denial of service (billion laughs).",
         ["XML request bodies", "SVG/DOCX/XLSX uploads", "SOAP endpoints"],
         ["<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><x>&e;</x>",
          "<!ENTITY e SYSTEM 'http://<oast>/'>"],
         ["file contents in the response", "out-of-band callback", "parser error revealing paths"],
         Verify(*VERIFY_OAST),
         "Disable DOCTYPE/external entities in the XML parser; prefer non-XML formats.",
         [_REF["owasp_web"], _REF["cwe"] + "definitions/611.html"],
         ["code_audit CA-XXE"], "tentative"),

    Vuln("ssti", "Server-Side Template Injection", "Server-Side Injection", HIGH, "CWE-1336", "A03", "API8", "CAPEC-242",
         "server_side_injection.ssti",
         "User input is rendered as a template expression, often leading to RCE.",
         "Remote code execution, data disclosure, depending on the template engine sandbox.",
         ["fields rendered back via a template", "email/name templating", "report generators"],
         ["{{7*7}}", "${7*7}", "#{7*7}", "{{config.items()}}"],
         ["arithmetic evaluated (49)", "object/config leakage", "command output"],
         Verify(*VERIFY_MANUAL),
         "Never render user input as a template; use logic-less templates with auto-escaping; sandbox the engine.",
         [_REF["owasp_web"], _REF["cwe"] + "definitions/1336.html"],
         ["code_audit CA-SSTI"], "tentative"),

    Vuln("path_traversal", "Path Traversal / LFI", "Server-Side Injection", HIGH, "CWE-22", "A01", "API8", "CAPEC-126",
         "server_side_injection.file_inclusion_local",
         "User input controls a file path, allowing access outside the intended directory.",
         "Read sensitive files (/etc/passwd, config, secrets), sometimes local file inclusion → RCE.",
         ["file/path/page/template/download params", "include/require targets"],
         ["../../../../etc/passwd", "..%2f..%2f", "....//....//"],
         ["file contents returned", "differing errors for valid vs invalid paths"],
         Verify(*VERIFY_MANUAL),
         "Resolve to a canonical path and confirm it is within an allow-listed base dir; never use raw input as a path.",
         [_REF["owasp_web"], _REF["cwe"] + "definitions/22.html"],
         ["code_audit CA-LFI", "mobile_audit (n/a)"], "firm"),

    Vuln("open_redirect", "Open Redirect", "Unvalidated Redirects and Forwards", LOW, "CWE-601", "A01", "", "CAPEC-194",
         "unvalidated_redirects.open_redirect",
         "A redirect target is taken from user input without validation.",
         "Phishing (trusted domain → attacker site), OAuth token theft via redirect_uri abuse.",
         ["next/redirect/return/url/dest params", "OAuth redirect_uri"],
         ["//evil.com", "https://evil.com", "/\\evil.com"],
         ["302 to an external attacker domain", "token leaked to the redirect host"],
         Verify(*VERIFY_MANUAL),
         "Allow-list redirect targets or use relative paths only; never redirect to a raw input value.",
         [_REF["owasp_web"], _REF["cwe"] + "definitions/601.html"],
         ["code_audit CA-REDIR"], "tentative"),

    Vuln("auth", "Authentication Failures", "Broken Authentication and Session Management", HIGH, "CWE-287", "A07", "API2", "CAPEC-115",
         "broken_authentication_and_session_management.authentication_bypass",
         "Weaknesses that let an attacker bypass or weaken authentication.",
         "Account takeover, unauthorized access, credential-stuffing at scale.",
         ["login", "password reset", "session cookies", "MFA flows", "'remember me' tokens"],
         ["weak/removed password policy", "reuse of a session after logout", "reset-token reuse", "host-header poisoning on reset"],
         ["login without valid credentials", "session reused post-logout", "reset link abuse", "MFA skipped"],
         Verify(*VERIFY_MANUAL),
         "Strong password policy, rate limiting + lockout, MFA, invalidate sessions on logout/reset, single-use scoped reset tokens.",
         [_REF["owasp_web"], _REF["cwe"] + "definitions/287.html", _REF["wstg"]],
         ["code_audit CA-PLAINTEXTPW", "web_probe (cookie flags)", "manual/agentic auth analyzer"],
         "dynamic-only"),

    Vuln("jwt", "JWT Problems", "Broken Authentication and Session Management", HIGH, "CWE-347", "A07", "API2", "CAPEC-115",
         "broken_authentication_and_session_management.jwt_signature_not_verified",
         "Flaws in JSON Web Token handling that let an attacker forge or tamper with tokens.",
         "Full authentication bypass, privilege escalation to admin, impersonation of any user.",
         ["Authorization: Bearer tokens", "session JWTs in cookies/localStorage"],
         ["alg:none", "HS256 with a weak/known secret", "kid path traversal", "expired token still accepted", "flip isAdmin claim"],
         ["a forged token is accepted", "role/claim change grants access", "unsigned token honoured"],
         Verify(*VERIFY_STATIC),
         "Pin the algorithm server-side; verify the signature with a strong secret/key; validate exp/aud/iss; never trust client claims.",
         [_REF["owasp_web"], _REF["cwe"] + "definitions/347.html"],
         ["code_audit CA-JWT-NONE", "code_audit CA-JWT-NOVERIFY", "code_audit CA-JWT-SECRET"],
         "firm"),

    Vuln("file_upload", "File Upload Vulnerabilities", "Unrestricted File Upload", HIGH, "CWE-434", "A04", "API8", "CAPEC-17",
         "unrestricted_file_upload.arbitrary_file_upload",
         "Insufficient validation of uploaded files lets an attacker store dangerous content.",
         "RCE via web-shell (PHP/JSP/ASPX), stored XSS via SVG/HTML, path traversal via crafted filenames, DoS via zip bombs.",
         ["file upload endpoints", "avatar/document/import features"],
         ["shell.php via double extension shell.php.jpg", "SVG with <script>", "Content-Type/magic-byte bypass", "../ in filename", "zip slip"],
         ["uploaded script executes when requested", "stored XSS fires", "file written outside the upload dir"],
         Verify(*VERIFY_MANUAL),
         "Validate type by magic bytes + allow-list extension; store outside webroot with a random name; serve with a safe Content-Type; scan archives.",
         [_REF["owasp_web"], _REF["cwe"] + "definitions/434.html"],
         ["code_audit CA-UPLOAD", "manual/agentic file-upload analyzer"], "firm"),

    Vuln("api_security", "API Security Issues", "Broken Access Control", HIGH, "CWE-285", "A01", "API1", "CAPEC-180",
         "broken_access_control.idor",
         "API-specific access-control and design flaws: BOLA/BFLA/BOPLA, mass assignment, exposed docs, missing limits.",
         "Unauthorized object/function access, privilege escalation, data exposure, abuse of undocumented endpoints.",
         ["REST/GraphQL endpoints", "object ids", "admin functions", "object properties (isAdmin)", "swagger/openapi/graphql introspection"],
         ["swap object id (BOLA)", "call POST /admin/* as a user (BFLA)", "set isAdmin:true in body (BOPLA/mass-assign)", "GraphQL __schema introspection"],
         ["cross-tenant data", "admin function succeeds as a user", "privileged field accepted", "hidden endpoint responds"],
         Verify(*VERIFY_DIFFERENTIAL),
         "Enforce object- AND function-level authorization server-side; allow-list writable fields; disable introspection/docs in prod; add rate limits.",
         [_REF["owasp_api"], _REF["cwe"] + "definitions/285.html"],
         ["code_audit CA-IDOR", "code_audit CA-MASSASSIGN", "code_audit CA-GRAPHQL", "code_audit CA-SWAGGER", "web_attack differential oracle"],
         "heuristic"),

    Vuln("mass_assignment", "Mass Assignment / BOPLA", "Broken Access Control", MED, "CWE-915", "A01", "API3", "CAPEC-1",
         "broken_access_control.mass_assignment",
         "A request object is bound wholesale to a model, letting a client set fields it shouldn't (e.g. isAdmin, balance).",
         "Privilege escalation, tampering with server-controlled fields, financial abuse.",
         ["create/update endpoints that bind req.body to a model"],
         ["add isAdmin:true / role:admin / verified:true to the JSON body", "set a foreign owner_id"],
         ["privileged field persisted", "role/ownership changed by a normal user"],
         Verify(*VERIFY_MANUAL),
         "Bind only an explicit allow-list of fields; never spread req.body into a model; separate input DTOs from entities.",
         [_REF["owasp_api"], _REF["cwe"] + "definitions/915.html"],
         ["code_audit CA-MASSASSIGN"], "tentative"),

    Vuln("business_logic", "Business Logic Flaws", "Application Logic", HIGH, "CWE-840", "A04", "API6", "CAPEC-210",
         "insecure_design.business_logic",
         "The application enforces its rules incorrectly, so a valid-looking sequence of requests produces an invalid outcome.",
         "Financial loss (₹0 orders, double refunds, unlimited coupons), reward farming, quota/limit bypass.",
         ["checkout/payment flows", "coupon/discount logic", "refund/withdrawal", "multi-step workflows", "concurrent requests (race conditions)"],
         ["apply a coupon repeatedly", "negative quantity/price", "double-submit a withdrawal (race)", "skip a required step"],
         ["order total goes to/below zero", "duplicate credit/reward", "step bypassed", "limit exceeded"],
         Verify(*VERIFY_MANUAL),
         "Enforce invariants server-side (price ≥ 0, one-time coupons, idempotency keys); use atomic transactions/locks against races.",
         [_REF["owasp_web"], _REF["cwe"] + "definitions/840.html"],
         ["manual/agentic business-logic engine"], "dynamic-only"),

    Vuln("csrf", "Cross-Site Request Forgery", "Cross-Site Request Forgery", MED, "CWE-352", "A01", "", "CAPEC-62",
         "cross_site_request_forgery.application_wide",
         "A state-changing request is accepted using only ambient cookies, so another site can trigger it.",
         "Actions performed as the victim: change email/password, transfer funds, alter settings.",
         ["state-changing POST/PUT/DELETE without a CSRF token", "cookies without SameSite"],
         ["cross-site form auto-submit", "missing/removed CSRF token still accepted"],
         ["action succeeds without a valid anti-CSRF token", "cookie sent cross-site"],
         Verify(*VERIFY_STATIC),
         "Synchroniser/double-submit CSRF tokens on state-changing requests; SameSite=Lax/Strict cookies; re-auth for sensitive actions.",
         [_REF["owasp_web"], _REF["cwe"] + "definitions/352.html"],
         ["code_audit CA-CSRF", "web_probe (SameSite)"], "tentative"),

    Vuln("weak_crypto", "Cryptographic Failures", "Cryptographic Weakness", MED, "CWE-327", "A02", "API8", "CAPEC-97",
         "cryptographic_weakness.broken_cryptography",
         "Weak or misused cryptography — broken hashes/ciphers, hard-coded keys, cleartext transport.",
         "Password cracking, data decryption, token forgery, MITM interception of sensitive data.",
         ["password hashing", "at-rest encryption", "TLS config", "IV/nonce/key handling", "RNG for secrets"],
         ["MD5/SHA1 for passwords", "DES/3DES/RC4 or ECB mode", "hard-coded key/IV", "HTTP for sensitive data", "predictable Random()"],
         ["weak algorithm identified in source", "cleartext transport observed", "hard-coded secret"],
         Verify(*VERIFY_STATIC),
         "Argon2id/bcrypt for passwords; AES-GCM with random IVs; TLS everywhere; keys from a KMS/secret store; use a CSPRNG.",
         [_REF["owasp_web"], _REF["cwe"] + "definitions/327.html"],
         ["code_audit CA-HASH/CA-CIPHER/CA-IV/CA-SEED/CA-HTTP/CA-TLSVERIFY",
          "mobile_audit MA-WEAK-HASH/MA-WEAK-CIPHER/MA-HARDCODE-KEY/MA-WEAK-RNG"],
         "tentative"),
]

_BY_ID = {v.id: v for v in KB}
_ALIASES = {
    "sql": "sqli", "sql_injection": "sqli", "cross_site_scripting": "xss",
    "insecure_direct_object_reference": "idor", "bola": "idor",
    "server_side_request_forgery": "ssrf", "rce": "command_injection",
    "cmdi": "command_injection", "os_command_injection": "command_injection",
    "lfi": "path_traversal", "authentication": "auth", "jwt_problems": "jwt",
    "upload": "file_upload", "api": "api_security", "bopla": "mass_assignment",
    "logic": "business_logic", "crypto": "weak_crypto", "cryptographic_failures": "weak_crypto",
}


def get(name: str) -> Vuln | None:
    key = name.strip().lower().replace("-", "_").replace(" ", "_")
    if key in _BY_ID:
        return _BY_ID[key]
    if key in _ALIASES:
        return _BY_ID[_ALIASES[key]]
    return None


def all_vulns() -> list[Vuln]:
    return list(KB)


# ── Risk scoring engine: combine severity + confidence + verification + EPSS ──
_SEV_BASE = {CRIT: 9.5, HIGH: 8.0, MED: 5.5, LOW: 3.0, "info": 1.0}
_CONF_MULT = {"firm": 1.0, "confirmed": 1.0, "tentative": 0.8, "heuristic": 0.6,
              "inconclusive": 0.45, "dynamic-only": 0.7}


def compose_risk(severity: str, confidence: str = "firm",
                 exploit_verified: bool = False, epss: float | None = None) -> dict:
    """Blend the signals the spec asks for into one 0–10 score + a band.

    - severity: base weight (critical..low).
    - confidence: how sure the detector is (firm/tentative/heuristic…).
    - exploit_verified: an oracle CONFIRMED it live → full confidence + a bump.
    - epss: optional EPSS probability (0..1) from a live feed; nudges the score up.
    """
    base = _SEV_BASE.get(severity.lower(), 5.0)
    mult = 1.0 if exploit_verified else _CONF_MULT.get(confidence.lower(), 0.7)
    score = base * mult
    if exploit_verified:
        score = min(10.0, score + 0.5)   # a proven exploit is worth more than a lead
    if epss is not None:
        score = min(10.0, score + max(0.0, min(1.0, epss)) * 1.0)
    score = round(min(10.0, max(0.0, score)), 1)
    band = ("critical" if score >= 9 else "high" if score >= 7
            else "medium" if score >= 4 else "low")
    return {
        "score": score, "band": band,
        "factors": {"base_severity": severity, "confidence": confidence,
                    "exploit_verified": exploit_verified, "epss": epss},
    }


def _main() -> int:
    ap = argparse.ArgumentParser(description="Vulnerability knowledge base (definitions + how to verify).")
    ap.add_argument("name", nargs="?", help="a vuln id/name/alias (e.g. sqli, xss, 'jwt problems'); omit to list all")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if not args.name:
        if args.json:
            print(json.dumps([v.to_dict() for v in KB], indent=2))
            return 0
        print(f"Vulnerability knowledge base — {len(KB)} classes\n")
        for v in KB:
            owasp = "/".join(x for x in (v.owasp_web, v.owasp_api) if x)
            print(f"  {v.id:18} {v.name:32} {v.cwe:9} OWASP {owasp or '-':10} verify:{v.verify.method}")
        return 0

    v = get(args.name)
    if not v:
        print(f"Unknown: {args.name}. Try one of: {', '.join(x.id for x in KB)}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(v.to_dict(), indent=2))
        return 0
    owasp = "/".join(x for x in (v.owasp_web, v.owasp_api) if x)
    print(f"# {v.name}  ({v.id})\n")
    print(f"Category   : {v.category}")
    print(f"Severity   : {v.severity}   CWE {v.cwe}   OWASP {owasp}   {v.capec}   VRT {v.vrt}")
    print(f"\nWhat it is : {v.description}")
    print(f"Impact     : {v.impact}")
    print(f"\nWhere      : {', '.join(v.where)}")
    print(f"Payloads   : {', '.join(v.payloads)}")
    print(f"Evidence   : {', '.join(v.evidence)}")
    print(f"\nVerify     : [{v.verify.method}] {v.verify.how}")
    print(f"Confidence : {v.static_confidence}")
    print(f"Engines    : {', '.join(v.engines)}")
    print(f"\nRemediation: {v.remediation}")
    print(f"References : {', '.join(v.references)}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
