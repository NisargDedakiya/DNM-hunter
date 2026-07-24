"""Web-application source SAST — the classic server-side/web VRT classes.

Covers the Bugcrowd VRT rows that are genuinely detectable from source code
(as opposed to a live target): server-side injection (SQLi, command
injection/RCE, XXE, local file inclusion, SSTI, LDAP injection, CRLF/response
splitting, path traversal, SSRF), unvalidated redirects, cross-site scripting
sinks, cryptographic weakness, insecure deserialization, insecure randomness,
and a few high-signal misconfigurations (Flask debug, plaintext secret storage).

Design mirrors llm_audit: line-anchored regex rules plus light intra-file taint
so injection sinks fire on *user-controlled* data, not on constants. Language
coverage: Python and JavaScript/TypeScript, with language-agnostic crypto rules.
Every finding carries a `vrt` id so the platform can roll findings up to the
Bugcrowd taxonomy.

CLI:  python -m code_audit <path> [--json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

CRIT, HIGH, MED, LOW, INFO = "critical", "high", "medium", "low", "info"

_SRC_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".php"}
_SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".next",
              "__pycache__", ".venv", "venv", "site-packages", "migrations"}

# ── user-input taint sources (Python + JS/TS + PHP web frameworks) ──
_USER_INPUT = re.compile(
    r"(request\.(args|form|values|json|data|files|GET|POST|body|query|params|cookies|headers)"
    r"|req\.(body|query|params|cookies|headers)"
    r"|\.args\.get|\.get_json|flask\.request|self\.get_argument"
    r"|params\[|query\[|body\[|\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV)"
    r"|php://input|apache_request_headers|getallheaders"
    r"|url\.searchParams|process\.argv|input\s*\()", re.IGNORECASE)
# variable assigned from a user-input source → tainted
_INPUT_ASSIGN = re.compile(
    r"\b(?:const|let|var\s+)?([A-Za-z_]\w*)\s*=\s*[^=].*?(" + _USER_INPUT.pattern + r")",
    re.IGNORECASE)


def _interpolates(line: str, var: str) -> bool:
    v = re.escape(var)
    return bool(
        re.search(r"[{$]\{?\s*" + v + r"\b", line)          # f"{var}" / `${var}`
        or re.search(r"[+%]\s*" + v + r"\b", line)           # + var / % var
        or re.search(r"\b" + v + r"\s*[+]", line)            # var +
        or re.search(r"\.format\([^)]*\b" + v + r"\b", line)  # .format(var)
        or re.search(r"%\s*\(?\s*" + v + r"\b", line))        # % (var)


@dataclass
class CodeFinding:
    vrt: str            # VRT id, e.g. "server_side_injection.sql_injection"
    rule_id: str
    severity: str
    title: str
    file: str
    line: int
    detail: str
    cwe: str = ""
    # How exploitable this looks, purely from static evidence (the scanner does
    # not execute the target). "firm" = user input provably reaches a dangerous
    # sink with no sanitiser, or a definitive misconfiguration → likely
    # exploitable. "tentative" = a risky pattern whose exploitability depends on
    # context → verify. "heuristic" = a lead that requires manual review (e.g.
    # authorization/ownership for IDOR). True runtime confirmation is the job of
    # the dynamic scanner (web_probe) or a manual PoC.
    confidence: str = "firm"

    def to_dict(self) -> dict:
        return asdict(self)


# ── Taint-sensitive injection sinks. Each: (vrt, rule, sev, cwe, title, sink-regex) ──
# These fire only when the sink argument carries user input (direct or via a
# tainted variable), so constants and parameterised queries are not flagged.
_TAINT_SINKS = [
    ("server_side_injection.sql_injection", "CA-SQLI", CRIT, "CWE-89",
     "SQL query built from untrusted input (SQL injection)",
     re.compile(r"\b(execute|executemany|executescript|query|raw|cursor\.execute|\.query|db\.execute|sequelize\.query)\s*\(", re.IGNORECASE)),
    ("server_side_injection.rce", "CA-CMDI", CRIT, "CWE-78",
     "OS command built from untrusted input (command injection / RCE)",
     re.compile(r"\b(os\.system|os\.popen|subprocess\.(?:run|call|Popen|check_output|check_call)|commands\.getoutput|child_process\.(?:exec|execSync|spawn|spawnSync)|shell_exec|passthru|proc_open)\s*\(", re.IGNORECASE)),
    ("server_side_injection.rce", "CA-EVAL", CRIT, "CWE-95",
     "Untrusted input passed to a code-evaluation sink (RCE)",
     re.compile(r"\b(eval|exec|execfile|Function|vm\.runInNewContext|vm\.runInThisContext)\s*\(")),
    ("server_side_injection.file_inclusion_local", "CA-LFI", HIGH, "CWE-98",
     "File path built from untrusted input (local file inclusion / path traversal)",
     re.compile(r"\b(open|io\.open|codecs\.open|send_file|send_from_directory|sendFile|res\.sendFile|readFile|readFileSync|include|require|fs\.readFile)\s*\(", re.IGNORECASE)),
    ("server_side_injection.ssti", "CA-SSTI", HIGH, "CWE-1336",
     "Untrusted input rendered as a template (server-side template injection)",
     re.compile(r"\b(render_template_string|Template\s*\(|from_string|env\.from_string|Jinja2?\.)\b")),
    ("server_side_injection.ssrf", "CA-SSRF", HIGH, "CWE-918",
     "Outbound request to an untrusted URL (server-side request forgery)",
     re.compile(r"\b(requests\.(?:get|post|put|delete|head|request)|urllib\.request\.urlopen|urlopen|httpx\.(?:get|post)|axios\.(?:get|post)|fetch|http\.get|got\s*\()\s*\(", re.IGNORECASE)),
    ("server_side_injection.ldap_injection", "CA-LDAP", HIGH, "CWE-90",
     "LDAP filter built from untrusted input (LDAP injection)",
     re.compile(r"\b(search_s|search_ext_s|\.search\s*\(|ldap\.(?:search|filter))", re.IGNORECASE)),
    ("unvalidated_redirects.open_redirect", "CA-REDIR", MED, "CWE-601",
     "Redirect target built from untrusted input (open redirect)",
     re.compile(r"\b(redirect|res\.redirect|res\.location|HttpResponseRedirect|sendRedirect|window\.location|location\.href)\s*(\(|=)", re.IGNORECASE)),
    ("cross_site_scripting.stored", "CA-XSS", HIGH, "CWE-79",
     "Untrusted input written to an HTML/DOM sink (cross-site scripting)",
     re.compile(r"\b(innerHTML|outerHTML|document\.write|document\.writeln|insertAdjacentHTML|\.html\s*\(|dangerouslySetInnerHTML|v-html|res\.send|res\.write)\b")),
    ("server_side_injection.http_response_manipulation", "CA-CRLF", MED, "CWE-113",
     "HTTP header/response built from untrusted input (response splitting / CRLF)",
     re.compile(r"\b(set_header|setHeader|add_header|response\.headers\[|res\.set|res\.header|writeHead|Location:)\b", re.IGNORECASE)),
    # File upload — a user-controlled filename/path reaches a file-write sink
    # (arbitrary upload / path traversal). model.save() with no args won't fire.
    ("unrestricted_file_upload.arbitrary_file_upload", "CA-UPLOAD", HIGH, "CWE-434",
     "User-controlled filename/path written to disk (unrestricted file upload / path traversal)",
     # No leading \b: `.save` must match after `]`/`)` too (e.g.
     # request.files["f"].save(...)), where a word boundary would fail.
     re.compile(r"(\.save|writeFileSync|writeFile|createWriteStream|move_uploaded_file|copyfileobj|shutil\.copy(?:file)?|os\.rename)\s*\(", re.IGNORECASE)),
    # IDOR (heuristic) — a user-controlled identifier flows into an object
    # lookup. Static analysis cannot see the authorization/ownership check, so
    # this is a lead to review, not a confirmed bug.
    ("broken_access_control.idor", "CA-IDOR", MED, "CWE-639",
     "User-controlled object identifier used in a data lookup (possible IDOR)",
     re.compile(r"\b(objects\.get|objects\.filter|get_object_or_404|get_or_404|findById|findByPk|\.findOne|\.find_one|\.query\.get|prisma\.\w+\.(?:findUnique|findFirst))\s*\(", re.IGNORECASE)),
    # CSV/formula injection — untrusted data written to a spreadsheet cell. A
    # leading =/+/-/@ makes the value a formula when the file is opened in Excel.
    ("external_behavior.csv_injection", "CA-CSV", MED, "CWE-1236",
     "Untrusted input written to a CSV/spreadsheet cell (formula/CSV injection)",
     re.compile(r"\b(writerow|writerows|csv\.writer|\.writeRow|createObjectCsvWriter|\.addRow|writerow_dict|DictWriter)\s*\(|\.writeRecords\s*\(", re.IGNORECASE)),
]

# ── Context-free rules (no taint needed): (vrt, rule, sev, cwe, title, regex, langs) ──
_STATIC_RULES = [
    # Cryptographic weakness — weak/broken primitives
    ("cryptographic_weakness.weak_hash", "CA-HASH", MED, "CWE-327",
     "Weak/broken hash used for security (MD5/SHA1)",
     re.compile(r"\b(hashlib\.(md5|sha1)|MD5|createHash\s*\(\s*['\"]md5['\"]|createHash\s*\(\s*['\"]sha1['\"]|MessageDigest\.getInstance\s*\(\s*['\"](MD5|SHA-?1)['\"])", re.IGNORECASE)),
    ("cryptographic_weakness.broken_cryptography", "CA-CIPHER", HIGH, "CWE-327",
     "Broken/weak cipher (DES/3DES/RC4/Blowfish or ECB mode)",
     re.compile(r"\b(DES\b|TripleDES|3DES|ARC4|RC4|Blowfish|MODE_ECB|['\"]des-|['\"]rc4|/ECB/|Cipher\.getInstance\s*\(\s*['\"]DES)", re.IGNORECASE)),
    # NOTE: CA-RANDOM (insecure RNG) is NOT a context-free rule — a bare
    # Math.random() is overwhelmingly legitimate (animation, particles, jitter).
    # It is handled by the security-context-gated pass _scan_insecure_rng below,
    # which only fires when the value feeds a token/secret/session/key/etc.
    ("cryptographic_weakness.insecure_key_generation", "CA-RSAKEY", MED, "CWE-326",
     "Undersized asymmetric key (<2048-bit RSA/DSA)",
     re.compile(r"(key_size\s*=\s*(512|768|1024)\b|RSA\.generate\s*\(\s*(512|768|1024)\b|modulusLength\s*:\s*(512|768|1024)\b)")),
    # Insecure deserialization (RCE-class)
    ("server_side_injection.rce", "CA-DESERIAL", HIGH, "CWE-502",
     "Insecure deserialization of untrusted data (pickle/yaml.load/marshal/node-serialize)",
     re.compile(r"\b(pickle\.loads?|cPickle\.loads?|_pickle\.loads?|yaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)|marshal\.loads?|jsonpickle\.decode|node-serialize|unserialize\s*\(|readObject\s*\()", re.IGNORECASE)),
    # XXE — XML parser with external entities not disabled
    ("server_side_injection.xxe", "CA-XXE", HIGH, "CWE-611",
     "XML parsed with external entities enabled (XXE)",
     re.compile(r"(etree\.(?:parse|fromstring|XMLParser)\s*\((?![^)]*resolve_entities\s*=\s*False)|lxml\.etree|xml\.dom\.minidom|xml\.sax|libxml_disable_entity_loader\s*\(\s*false|DocumentBuilderFactory|SAXParserFactory|XMLReaderFactory|noent\s*=\s*True|resolve_entities\s*=\s*True)")),
    # Framework debug / verbose errors (sensitive data exposure)
    ("sensitive_data_exposure.debug_page", "CA-DEBUG", MED, "CWE-489",
     "Debug mode enabled (verbose error/debug page in production)",
     re.compile(r"(app\.run\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True|app\.config\[['\"]DEBUG['\"]\]\s*=\s*True|FLASK_DEBUG\s*=\s*1|NODE_ENV.{0,6}development)")),
    # Insecure transport
    ("insecure_data_transport.cleartext", "CA-HTTP", LOW, "CWE-319",
     "Sensitive request over cleartext HTTP",
     re.compile(r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|schemas?\.|www\.w3\.org|xmlns)", re.IGNORECASE)),
    # Cookie / session flags (server-side misconfig, detectable in code)
    ("server_security_misconfiguration.cookie_flags", "CA-COOKIE", LOW, "CWE-614",
     "Cookie set without Secure/HttpOnly flags",
     re.compile(r"(set_cookie\s*\((?![^)]*(secure\s*=\s*True|httponly\s*=\s*True))|res\.cookie\s*\((?![^)]*(secure\s*:\s*true|httpOnly\s*:\s*true)))", re.IGNORECASE)),
    # Insecure data storage — client token in web storage
    ("insecure_data_storage.web_storage_token", "CA-WEBSTORE", LOW, "CWE-922",
     "Sensitive token stored in localStorage/sessionStorage",
     re.compile(r"(localStorage|sessionStorage)\.setItem\s*\(\s*['\"][^'\"]*(token|jwt|secret|password|session|auth)", re.IGNORECASE)),
    # TLS verification disabled
    ("insecure_data_transport.tls_verify_disabled", "CA-TLSVERIFY", MED, "CWE-295",
     "TLS certificate verification disabled",
     re.compile(r"(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFYPEER.{0,10}(0|false)|ssl\._create_unverified_context|InsecureSkipVerify\s*:\s*true|check_hostname\s*=\s*False)", re.IGNORECASE)),
    # JWT: 'none' algorithm accepted — signature is not verified (auth bypass)
    ("broken_authentication_and_session_management.jwt_signature_not_verified", "CA-JWT-NONE", HIGH, "CWE-347",
     "JWT 'none' algorithm accepted — signature not verified (authentication bypass)",
     re.compile(r"(algorithms?\s*[:=]\s*\[?\s*['\"]none['\"]|['\"]alg['\"]\s*:\s*['\"]none['\"])", re.IGNORECASE)),
    # JWT: signature verification explicitly disabled (auth bypass)
    ("broken_authentication_and_session_management.jwt_signature_not_verified", "CA-JWT-NOVERIFY", HIGH, "CWE-347",
     "JWT signature verification disabled (authentication bypass)",
     re.compile(r"(jwt\.decode\s*\([^)]*verify\s*=\s*False|verify_signature['\"]?\s*[:=]\s*(?:False|false)|jwt\.decode\s*\([^)]*['\"]verify['\"]\s*:\s*(?:false|False))", re.IGNORECASE)),
    # JWT: hard-coded signing secret in source
    ("broken_authentication_and_session_management.weak_jwt_secret", "CA-JWT-SECRET", MED, "CWE-321",
     "Hard-coded JWT signing secret in source",
     re.compile(r"(jwt\.encode\s*\([^)]*,\s*['\"][^'\"]{3,}['\"]|jwt\.sign\s*\([^)]*,\s*['\"][^'\"]{3,}['\"]|(?:jwt_secret|jwtsecret|secretorkey|jwt_signing_key)\s*[:=]\s*['\"][^'\"]{4,}['\"])", re.IGNORECASE)),
    # CORS: reflected origin, or wildcard origin together with credentials
    ("server_security_misconfiguration.cors_misconfiguration", "CA-CORS", MED, "CWE-942",
     "Permissive CORS — reflected origin, or wildcard origin with credentials",
     re.compile(r"(Access-Control-Allow-Origin['\"]?\s*[:,][^;\n]*\b(?:req|request|origin)\b|origin\s*:\s*(?:true|['\"]\*['\"])[^)}\n]*credentials\s*:\s*true|credentials\s*:\s*true[^)}\n]*origin\s*:\s*(?:true|['\"]\*['\"]))", re.IGNORECASE)),
    # CSRF protection explicitly disabled/exempted (definitive misconfig → firm)
    ("cross_site_request_forgery.application_wide", "CA-CSRF", MED, "CWE-352",
     "CSRF protection disabled or exempted",
     # @csrf_exempt decorator or csrf_exempt(view) call — NOT the bare import.
     re.compile(r"(@csrf_exempt|csrf_exempt\s*\(|@csrf\.exempt|csrf\s*[:=]\s*(?:False|false)|csrfProtection\s*[:=]\s*(?:False|false)|WTF_CSRF_ENABLED\s*=\s*False|CSRF_ENABLED\s*=\s*False|SameSite\s*[:=]\s*['\"]?None)", re.IGNORECASE)),
    # Hard-coded / default credentials (P1 "Using Default Credentials")
    ("server_security_misconfiguration.using_default_credentials", "CA-DEFAULTCRED", HIGH, "CWE-798",
     "Hard-coded or default credentials in source",
     re.compile(r"((?:password|passwd|pwd|admin_pass|db_pass|default_password)\s*[:=]\s*['\"](?:admin|password|passw0rd|changeme|root|123456|letmein|default|secret|test123)['\"]|username\s*[:=]\s*['\"]admin['\"][^\n]{0,40}password\s*[:=]\s*['\"])", re.IGNORECASE)),
    # GraphQL introspection / GraphiQL left enabled (schema disclosure)
    ("sensitive_data_exposure.graphql_introspection_enabled", "CA-GRAPHQL", LOW, "CWE-200",
     "GraphQL introspection / GraphiQL enabled (schema disclosure)",
     re.compile(r"(introspection['\"]?\s*[:=]\s*(?:True|true)|graphiql['\"]?\s*[:=]\s*(?:True|true)|GraphiQL|IntrospectionQuery|__schema\s*\{)", re.IGNORECASE)),
    # Predictable PRNG seed — deterministic randomness for a security value
    ("cryptographic_weakness.insufficient_entropy", "CA-SEED", MED, "CWE-337",
     "Predictable PRNG seed (deterministic randomness)",
     re.compile(r"(random\.seed\s*\(\s*(?:\d+|['\"]|0x)|np\.random\.seed\s*\(\s*\d|srand\s*\(\s*(?:\d+|time)|mt_srand\s*\(\s*\d)", re.IGNORECASE)),
    # Hard-coded / static IV or nonce — breaks CBC/GCM confidentiality
    ("cryptographic_weakness.insufficient_entropy", "CA-IV", MED, "CWE-329",
     "Hard-coded / static IV or nonce used for encryption",
     re.compile(r"\b(iv|nonce)\s*[:=]\s*(b?['\"][^'\"]{2,}['\"]|bytes\(\s*\d+\s*\)|['\"]\\?x00|Buffer\.alloc\s*\(\s*\d+\s*\)|new\s+byte\[)", re.IGNORECASE)),
    # Sensitive token/secret placed in a URL / query string (leaks via logs, Referer)
    ("sensitive_data_exposure.sensitive_token_in_url", "CA-TOKENURL", LOW, "CWE-598",
     "Sensitive token/secret placed in a URL query string",
     re.compile(r"[?&](?:access_token|api_?key|token|password|secret|session|auth)=['\"]?\s*[+`$]", re.IGNORECASE)),
    # NoSQL (MongoDB) injection — server-side JS ($where/$function) built from a
    # string, or a raw request object used directly as a query (operator injection).
    ("server_side_injection.nosql_injection", "CA-NOSQL", HIGH, "CWE-943",
     "NoSQL query built from untrusted input (server-side JS / operator injection)",
     re.compile(r"(\$where['\"]?\s*[:=]|\$function['\"]?\s*[:=]|\bmapReduce\s*\(|\.(?:find|findOne|find_one|updateOne|updateMany|deleteOne|deleteMany|remove|aggregate)\s*\(\s*\{[^}]*\b(?:req|request)\.(?:body|query|params|json|form|args|GET|POST))", re.IGNORECASE)),
    # Mass assignment / BOPLA — a whole request object is spread into a model,
    # letting a client set fields it shouldn't (e.g. isAdmin).
    ("broken_access_control.mass_assignment", "CA-MASSASSIGN", MED, "CWE-915",
     "Whole request object bound to a model (mass assignment / BOPLA)",
     re.compile(r"(\*\*(?:request|req)\.(?:json|form|data|body|POST|GET|args)|Object\.assign\s*\([^,]+,\s*req\.body|\.(?:create|update|updateOne|findByIdAndUpdate|findOneAndUpdate|save|insertMany|bulkCreate)\s*\(\s*req\.(?:body|query|params)|new\s+[A-Z]\w*\s*\(\s*req\.(?:body|query)\s*\)|\{\s*\.\.\.\s*req\.body\s*\})", re.IGNORECASE)),
    # Plaintext / unhashed password handling — a raw request password assigned to
    # a password field with no hashing on the line, or a plaintext comparison.
    ("sensitive_data_exposure.cleartext_storage_of_password", "CA-PLAINTEXTPW", MED, "CWE-256",
     "Password stored/compared in cleartext (no hashing)",
     re.compile(r"(\.password\s*=\s*(?:request|req)\.[a-z]|\bpassword\s*==\s*(?:request|req|input)\b|password\s*=\s*request\.(?:form|args|json|POST|values)\b)", re.IGNORECASE)),
    # Exposed API documentation / interactive explorer (schema & endpoint disclosure)
    ("server_security_misconfiguration.api_documentation_exposed", "CA-SWAGGER", LOW, "CWE-200",
     "API documentation / explorer exposed (Swagger / OpenAPI / ReDoc)",
     re.compile(r"(swagger-ui-express|SwaggerModule\.setup|swagger_ui_bundle|['\"]/api-docs['\"]|['\"]/swagger['\"]|\bredoc\b|springdoc|flask_swagger|apispec)", re.IGNORECASE)),
]

# Static rules whose match is a definitive misconfiguration (not context-
# dependent) — treated as firm rather than tentative.
_FIRM_STATIC = {"CA-JWT-NONE", "CA-JWT-NOVERIFY", "CA-CSRF"}
# Taint sinks that are only a lead, needing manual authorization/logic review.
_HEURISTIC_SINKS = {"CA-IDOR"}


# Sinks where the *query string itself* is assembled from input — flagging must
# be parameterisation-aware (a bound-parameter query is safe even with taint).
_QUERY_SINKS = {"CA-SQLI", "CA-LDAP"}

# Leading `\$?` so PHP assignments ($name = ...) are captured too; the sigil is
# dropped from the variable name, and `_refs` matches it back inside `$name`.
_ASSIGN_RE = re.compile(r"\s*(?:(?:const|let|var)\s+)?\$?([A-Za-z_]\w*)\s*=\s*([^=].*)$")

# PHP output-encoding functions — if one wraps the echoed value it is not XSS.
_PHP_XSS_SANITIZERS = re.compile(
    r"htmlspecialchars|htmlentities|filter_var|\bintval|\bfloatval|\(int\)|\(float\)"
    r"|urlencode|rawurlencode|json_encode|strip_tags|escapeshellarg", re.IGNORECASE)

# PHP-specific taint sinks (applied only to .php files). Same (vrt, rule, sev,
# cwe, title, regex) shape as _TAINT_SINKS.
_PHP_SINKS = [
    ("server_side_injection.sql_injection", "CA-SQLI", CRIT, "CWE-89",
     "SQL query built from untrusted input (SQL injection)",
     re.compile(r"\b(mysqli_query|mysql_query|mysqli_multi_query|pg_query|pg_send_query|sqlite_query|->prepare)\s*\(", re.IGNORECASE)),
    ("server_side_injection.rce", "CA-CMDI", CRIT, "CWE-78",
     "OS command built from untrusted input (command injection / RCE)",
     re.compile(r"\b(system|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(", re.IGNORECASE)),
    ("server_side_injection.rce", "CA-EVAL", CRIT, "CWE-95",
     "Untrusted input passed to a code-evaluation sink (RCE)",
     re.compile(r"\b(eval|assert|create_function)\s*\(", re.IGNORECASE)),
    # NOTE: PHP echo/print XSS is handled by the dedicated, taint-source-classified
    # + context-aware pass below (_scan_php_xss), not by this coarse sink — that
    # avoids the variable-name/substring collisions a bare `echo` matcher causes.
    ("server_side_injection.file_inclusion_local", "CA-LFI", HIGH, "CWE-98",
     "File path built from untrusted input (local file inclusion / path traversal)",
     re.compile(r"\b(include|include_once|require|require_once|fopen|file_get_contents|readfile|highlight_file|show_source)\b", re.IGNORECASE)),
    ("server_side_injection.ssrf", "CA-SSRF", HIGH, "CWE-918",
     "Outbound request to an untrusted URL (server-side request forgery)",
     re.compile(r"\b(curl_exec|curl_init|file_get_contents|fsockopen|get_headers)\s*\(", re.IGNORECASE)),
]


# ── PHP XSS: taint-source classification + context-aware output analysis ─────
# The reviewer's six asks live here: (1) taint tracking, (2) source
# classification, (3) context-aware encoding, (4) sanitiser recognition,
# (5) confidence scoring, (6) reflected/stored/potential typing. A dedicated
# pass (rather than a coarse `echo` matcher) because XSS verdict quality hinges
# on *where the data came from* and *what context it lands in*.

# request-controlled sources → reflected-XSS candidates.
_PHP_REQUEST_SRC = re.compile(
    r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b"
    r"|\$_SERVER\s*\[\s*['\"](?:QUERY_STRING|REQUEST_URI|PATH_INFO|HTTP_[A-Z_]+|PHP_SELF)"
    r"|php://input|apache_request_headers|getallheaders", re.IGNORECASE)
# values read back out of persistent storage → stored-XSS candidates.
_PHP_DB_SRC = re.compile(
    r"->\s*fetch(?:All|Column|Object)?\s*\(|->\s*query\s*\("
    r"|\bmysqli?_fetch_\w+\s*\(|\bpg_fetch_\w+\s*\(", re.IGNORECASE)
_PHP_SESSION_SRC = re.compile(r"\$_SESSION\b")
# casts / checks that make a value non-markup → safe to echo.
_PHP_INT_SAFE = re.compile(
    r"\bintval\s*\(|\(\s*int\s*\)|\bfloatval\s*\(|\(\s*float\s*\)|\bctype_digit\s*\(", re.IGNORECASE)
_PHP_VARREF = re.compile(r"\$([A-Za-z_]\w*)")
# echo / print / printf / short-echo tag — the HTML output sinks.
_PHP_ECHO = re.compile(r"<\?=|\b(?:echo|print|printf|vprintf)\b", re.IGNORECASE)

# built-in output encoders, by the context they make safe.
_PHP_SANI_HTML = ("htmlspecialchars", "htmlentities", "strip_tags", "filter_var", "filter_input")
_PHP_SANI_URL = ("urlencode", "rawurlencode")
_PHP_SANI_JS = ("json_encode",)
_DANGER = {"request": 3, "session": 2, "db": 1, "safe": 0}


def collect_php_sanitizers(texts: list[str]) -> set[str]:
    """Names of project-defined functions that wrap a built-in HTML encoder —
    e.g. `function sanitize($d){ return htmlspecialchars(strip_tags(trim($d))); }`.
    Recognising these (reviewer ask #4) stops the tool calling escaped output XSS."""
    names: set[str] = set()
    func_re = re.compile(r"function\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*\{", re.IGNORECASE)
    body_sani = re.compile(r"htmlspecialchars|htmlentities|strip_tags|filter_var", re.IGNORECASE)
    for text in texts:
        for m in func_re.finditer(text):
            body = text[m.end():m.end() + 400]
            if body_sani.search(body):
                names.add(m.group(1))
    return names


def _php_expr_class(expr: str, cls: dict[str, str]) -> str | None:
    """Source class of a PHP expression: request | session | db | (inherited) | None."""
    if _PHP_REQUEST_SRC.search(expr):
        return "request"
    if _PHP_SESSION_SRC.search(expr):
        return "session"
    if _PHP_DB_SRC.search(expr):
        return "db"
    best = None
    for v in _PHP_VARREF.findall(expr):
        c = cls.get(v)
        if c and c != "safe" and (best is None or _DANGER[c] > _DANGER[best]):
            best = c
    return best


def _classify_php_sources(lines: list[str], sanitizers: set[str]) -> dict[str, str]:
    """Per-file symbol table: {varname → most-dangerous source class seen}."""
    cls: dict[str, str] = {}
    sani = re.compile(
        r"\b(" + "|".join(re.escape(s) for s in
                          (*_PHP_SANI_HTML, *_PHP_SANI_URL, *_PHP_SANI_JS, *sanitizers)) + r")\s*\(")
    fe_re = re.compile(
        r"foreach\s*\(\s*(.+?)\s+as\s+(?:\$[A-Za-z_]\w*\s*=>\s*)?\$([A-Za-z_]\w*)\s*\)")

    def bump(var: str, newc: str | None) -> bool:
        if not newc:
            return False
        if _DANGER.get(newc, 0) > _DANGER.get(cls.get(var, "safe"), -1) or var not in cls:
            if cls.get(var) != newc:
                cls[var] = newc
                return True
        return False

    for _ in range(6):  # fixpoint — order-independent
        changed = False
        for raw in lines:
            fe = fe_re.search(raw)
            if fe:
                changed |= bump(fe.group(2), _php_expr_class(fe.group(1), cls))
                continue
            m = _ASSIGN_RE.match(raw)
            if not m:
                continue
            var, rhs = m.group(1), m.group(2)
            if _PHP_INT_SAFE.search(rhs) or sani.search(rhs):
                changed |= bump(var, "safe")
            else:
                changed |= bump(var, _php_expr_class(rhs, cls))
        if not changed:
            break
    return cls


def _php_output_context(before: str) -> str:
    """Where the echoed value lands, from the HTML to the left of the echo tag:
    js | url | attribute | html."""
    if re.search(r"<script\b[^>]*>[^<]*$", before, re.IGNORECASE) \
            or re.search(r"\bon\w+\s*=\s*(['\"])[^'\"]*$", before, re.IGNORECASE):
        return "js"
    if re.search(r"=\s*(['\"])[^'\"]*$", before):  # inside an attribute value
        if re.search(r"\b(?:href|src|action|formaction|data-\w+|location)\s*=\s*(['\"])[^'\"]*$",
                     before, re.IGNORECASE):
            return "url"
        return "attribute"
    return "html"


def _echo_sanitised(expr: str, ctx: str, sanitizers: set[str]) -> bool:
    """True if the echoed expression is wrapped by an encoder appropriate to ctx."""
    if _PHP_INT_SAFE.search(expr):
        return True
    ok = {"html": (*_PHP_SANI_HTML, *sanitizers),
          "attribute": (*_PHP_SANI_HTML, *sanitizers),
          "url": (*_PHP_SANI_URL, *_PHP_SANI_HTML),
          "js": _PHP_SANI_JS}[ctx]
    return any(re.search(r"\b" + re.escape(s) + r"\s*\(", expr) for s in ok)


_PHP_XSS_META = {
    # source class → (vrt, severity, confidence, type-label)
    "request": ("cross_site_scripting.reflected", HIGH, "firm", "Reflected"),
    "session": ("cross_site_scripting.stored", MED, "tentative", "Potential stored"),
    "db":      ("cross_site_scripting.stored", LOW, "heuristic", "Potential stored"),
}
_CTX_HINT = {
    "html": "HTML body context — HTML-encode with htmlspecialchars(…, ENT_QUOTES).",
    "attribute": "HTML attribute context — encode with htmlspecialchars(…, ENT_QUOTES) "
                 "so quotes can't break out of the attribute.",
    "url": "URL context — validate the scheme and urlencode() the value; an attacker "
           "value could inject javascript: or extra parameters.",
    "js": "JavaScript context — htmlspecialchars is NOT enough here; emit the value "
          "with json_encode() inside the script.",
}


def _scan_php_xss(lines: list[str], file: str, sanitizers: set[str]) -> list[CodeFinding]:
    """Context-aware, source-classified PHP XSS detection (reviewer asks #1–#6)."""
    cls = _classify_php_sources(lines, sanitizers)
    out: list[CodeFinding] = []
    seen: set[int] = set()
    for i, raw in enumerate(lines, 1):
        for em in _PHP_ECHO.finditer(raw):
            after = raw[em.end():]
            expr = re.split(r";|\?>", after, maxsplit=1)[0]  # the echoed expression
            if not expr.strip():
                continue
            # (2) classify the source of the echoed data — inline $_GET/$_SESSION/
            # ->fetch() as well as previously-classified variables.
            source = _php_expr_class(expr, cls)
            if source in (None, "safe"):
                continue  # constant / int / already-safe → not XSS (kills the FPs)
            # (3) context + (4) sanitiser recognition
            ctx = _php_output_context(raw[:em.start()])
            if _echo_sanitised(expr, ctx, sanitizers):
                continue
            if i in seen:  # one XSS finding per line is enough
                continue
            seen.add(i)
            vrt, sev, conf, label = _PHP_XSS_META[source]
            src_word = {"request": "untrusted request input", "session": "a session value",
                        "db": "a database value"}[source]
            title = f"{label} XSS — {src_word} echoed without output encoding"
            verify = (" Manual verification required: confirm the stored value can contain "
                      "markup and that no write-path encodes it." if source != "request" else "")
            detail = (f"{title}. {_CTX_HINT[ctx]}{verify} [VRT {vrt}; CWE-79]")
            out.append(CodeFinding(vrt, "CA-XSS", sev, title, file, i, detail,
                                   "CWE-79", conf))
    return out


# ── insecure RNG: security-context-gated (CWE-330) ───────────────────────────
# A non-crypto RNG is only a weakness when its output is used for a
# security-sensitive value. Flagging every Math.random() (animation, particles,
# jitter, demos) is the classic false-positive generator — so this pass reports
# only when the RNG result reaches a token/secret/session/key/… context.
_INSECURE_RNG = re.compile(
    r"\b(?:random\.(?:random|randint|randrange|getrandbits|choice|sample|shuffle)"
    r"|Math\.random|mt_rand|\bmt_srand|\brand)\s*\(", re.IGNORECASE)
# Names that make a value security-sensitive. `key` only in a compound
# (apiKey/secretKey/…) so it never matches a React `key=` prop or a dict key.
_SECURITY_NAME = re.compile(
    r"token|secret|session|jwt|csrf|xsrf|\botp\b|passw|pwd|nonce|salt|"
    r"(?:api|secret|private|public|signing|encryption|crypto|access|master|refresh)[_-]?key|"
    r"cookie|\bpin\b|credential|verifier|challenge|\bseed\b|\biv\b|hmac|signature|"
    r"\bmfa\b|\b2fa\b|recovery|activation|reset|\bnonce\b|passcode|auth(?!or)", re.IGNORECASE)
# Token-string idioms: Math.random().toString(36|16) is almost always id/token gen.
_RNG_TOKEN_IDIOM = re.compile(
    r"\.random\s*\(\s*\)\s*\.\s*toString\s*\(\s*(?:16|36)\s*\)", re.IGNORECASE)
# LHS of an assignment / object-literal key on the RNG line.
_RNG_LHS = re.compile(
    r"^\s*(?:(?:const|let|var|final|readonly|private|public|protected|static)\s+)*"
    r"([\w.$\[\]'\"-]+?)\s*[:=](?![=>])")


def _scan_insecure_rng(lines: list[str], file: str, is_py: bool) -> list[CodeFinding]:
    vrt, cwe = "cryptographic_weakness.insufficient_entropy", "CWE-330"
    title = "Insecure RNG used for a security value (use a CSPRNG)"
    detail = (f"{title}. A non-cryptographic PRNG feeds a security-sensitive value — its "
              f"output is predictable. Use a CSPRNG (secrets / crypto.randomBytes / os.urandom).")
    out: list[CodeFinding] = []

    # Pass 1: vars assigned directly from an insecure RNG (for light flow tracking).
    rng_vars: set[str] = set()
    for raw in lines:
        code = raw.split("#", 1)[0] if is_py else raw
        if _INSECURE_RNG.search(code):
            m = _RNG_LHS.match(code)
            if m:
                name = m.group(1).split(".")[-1].strip("[]'\"")
                if name and not _SECURITY_NAME.search(name):
                    rng_vars.add(name)

    for i, raw in enumerate(lines, 1):
        code = raw.split("#", 1)[0] if is_py else raw
        rng_here = bool(_INSECURE_RNG.search(code))
        lhs = ""
        m = _RNG_LHS.match(code)
        if m:
            lhs = m.group(1)

        confidence = None
        # (a) RNG on this line whose target / idiom is security-sensitive → firm.
        if rng_here and (_RNG_TOKEN_IDIOM.search(code) or (lhs and _SECURITY_NAME.search(lhs))):
            confidence = "firm"
        # (b) a security-named var is assigned from an RNG-tainted var → tentative.
        elif lhs and _SECURITY_NAME.search(lhs) and _refs(code, rng_vars):
            confidence = "tentative"
        if confidence:
            out.append(CodeFinding(vrt, "CA-RANDOM", MED, title, file, i, detail, cwe, confidence))
    return out


def _refs(text: str, vars_: set[str]) -> bool:
    return any(re.search(r"\b" + re.escape(v) + r"\b", text) for v in vars_)


def _string_interp(rhs: str) -> bool:
    """RHS assembles a string via f-string/template/concat/%-format/.format —
    but NOT a bare `%s`/`?` placeholder inside a literal (that's parameterised)."""
    return bool(
        re.search(r"f['\"][^'\"]*\{", rhs)          # f"...{x}"
        or re.search(r"`[^`]*\$\{", rhs)             # `...${x}`
        or ".format(" in rhs
        or re.search(r"['\"]\s*\+", rhs)             # "..." + x
        or re.search(r"\+\s*[frb]?['\"]", rhs)       # x + "..."
        or re.search(r"['\"]\s*%\s*[\(\w]", rhs)     # "..." % (x)  (operator, not %s)
        or re.search(r"['\"]\s*\.\s*\$", rhs)        # "..." . $x   (PHP concat)
        or re.search(r"\$\w+\s*\.\s*['\"]", rhs)     # $x . "..."   (PHP concat)
        or re.search(r'"[^"]*\$\{?\w', rhs))         # "...$x..."   (PHP interpolation)


def _is_query_build(rhs: str, tainted: set[str]) -> bool:
    has_str = "'" in rhs or '"' in rhs or "`" in rhs
    return has_str and _string_interp(rhs) and (bool(_USER_INPUT.search(rhs)) or _refs(rhs, tainted))


def _looks_literal_only(arg_region: str) -> bool:
    """The sink is called on a single string/number literal — not user data."""
    return bool(re.match(r"\s*\(\s*(?:[rbf]?['\"][^'\"]*['\"]|\d+)\s*[,)]", arg_region))


def scan_code(text: str, file: str, php_sanitizers: set[str] | None = None) -> list[CodeFinding]:
    findings: list[CodeFinding] = []
    lines = text.splitlines()
    is_py = file.endswith(".py")
    is_php = file.endswith(".php")
    taint_sinks = _TAINT_SINKS + _PHP_SINKS if is_php else _TAINT_SINKS
    _seen: set[tuple] = set()

    # PHP XSS runs through the dedicated source-classified, context-aware pass.
    # `php_sanitizers` are project-defined encoders (found cross-file by
    # scan_tree); default to the local ones when scan_code is called standalone.
    if is_php:
        sani = php_sanitizers if php_sanitizers is not None else collect_php_sanitizers([text])
        findings.extend(_scan_php_xss(lines, file, sani))

    # Insecure RNG is context-gated (only flags security-sensitive use), across
    # all languages — replaces the old fire-on-every-Math.random() static rule.
    findings.extend(_scan_insecure_rng(lines, file, is_py))

    def add(vrt, rule, sev, title, i, detail, cwe="", confidence="firm"):
        # PHP and the generic rules can both match the same construct (e.g. a bare
        # `query(`); collapse identical (rule, line) hits.
        if (rule, i) in _seen:
            return
        _seen.add((rule, i))
        findings.append(CodeFinding(vrt, rule, sev, title, file, i, detail, cwe, confidence))

    # ── Light intra-file taint with transitive propagation ──
    # `tainted`    : vars carrying user-controlled data (directly or derived).
    # `sql_risky`  : vars whose value is a STRING assembled from tainted input
    #                (i.e. a query string an attacker helped build).
    tainted: set[str] = set()
    sql_risky: set[str] = set()
    for _ in range(6):  # iterate to a fixpoint so assignment order doesn't matter
        changed = False
        for raw in lines:
            code = raw.split("#", 1)[0] if is_py else raw
            m = _ASSIGN_RE.match(code)
            if not m:
                continue
            var, rhs = m.group(1), m.group(2)
            if (bool(_USER_INPUT.search(rhs)) or _refs(rhs, tainted)) and var not in tainted:
                tainted.add(var)
                changed = True
            if _is_query_build(rhs, tainted) and var not in sql_risky:
                sql_risky.add(var)
                changed = True
        if not changed:
            break

    for i, raw in enumerate(lines, 1):
        line = raw.split("#", 1)[0] if is_py else raw
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "*", "/*")):
            continue

        # taint-sensitive injection sinks
        for vrt, rule, sev, cwe, title, sink_rx in taint_sinks:
            m = sink_rx.search(line)
            if not m:
                continue
            arg_region = line[m.end() - 1:]  # from the "(" onward
            if _looks_literal_only(arg_region):
                continue
            # PHP echo/print of an output-encoded value is not XSS.
            if is_php and rule == "CA-XSS" and _PHP_XSS_SANITIZERS.search(line):
                continue
            if rule in _QUERY_SINKS:
                # only a string built from input is injectable; bound params are safe
                hit = _is_query_build(arg_region, tainted) or _refs(arg_region, sql_risky)
            else:
                # value sinks: dangerous whenever attacker data reaches the argument
                hit = bool(_USER_INPUT.search(arg_region)) or _refs(arg_region, tainted)
            if hit:
                heuristic = rule in _HEURISTIC_SINKS
                detail = (
                    f"{title}. A user-controlled identifier reaches this lookup — confirm "
                    f"an ownership/authorization check exists (heuristic; verify before reporting)."
                    if heuristic else
                    f"{title}. Untrusted data reaches this sink — use parameterisation / "
                    f"safe APIs / validation & output encoding."
                )
                add(vrt, rule, sev, title, i, detail, cwe,
                    confidence="heuristic" if heuristic else "firm")

        # context-free static rules
        jwt_verify_line = bool(re.search(r"jwt\.(?:decode|verify)", line, re.IGNORECASE))
        for vrt, rule, sev, cwe, title, rx in _STATIC_RULES:
            # `verify=False` inside jwt.decode(...) is a JWT signature bypass
            # (CA-JWT-NOVERIFY), not a TLS-verification issue — don't double-fire
            # the TLS rule and mislabel it.
            if rule == "CA-TLSVERIFY" and jwt_verify_line:
                continue
            if rx.search(line):
                add(vrt, rule, sev, title, i, f"{title}.", cwe,
                    confidence="firm" if rule in _FIRM_STATIC else "tentative")

    return findings


def scan_tree(root: str | Path) -> list[CodeFinding]:
    root = Path(root)
    files: list[tuple[Path, str]] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _SRC_EXT:
            continue
        if any(p in _SKIP_DIRS for p in path.parts):
            continue
        try:
            files.append((path, path.read_text(errors="replace")))
        except Exception:
            continue

    # First pass: harvest project-defined PHP sanitiser functions across the whole
    # tree so a custom encoder defined in one file is recognised when used in
    # another (e.g. functions.php's sanitize() used by index.php).
    php_sanitizers = collect_php_sanitizers(
        [t for p, t in files if p.suffix.lower() == ".php"])

    out: list[CodeFinding] = []
    for path, text in files:
        out.extend(scan_code(text, str(path.relative_to(root)), php_sanitizers))
    return out


def _main() -> int:
    ap = argparse.ArgumentParser(description="Web-application source SAST (VRT-mapped).")
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    p = Path(args.path)
    findings = scan_tree(p) if p.is_dir() else scan_code(p.read_text(errors="replace"), str(p))
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
        return 0
    for f in sorted(findings, key=lambda x: (x.severity, x.confidence)):
        print(f"  [{f.severity:8}] {f.confidence:9} {f.rule_id:12} {f.file}:{f.line}  {f.title}")
    firm = sum(1 for f in findings if f.confidence == "firm")
    tentative = sum(1 for f in findings if f.confidence == "tentative")
    heuristic = sum(1 for f in findings if f.confidence == "heuristic")
    print(f"\n{len(findings)} findings  ({firm} firm, {tentative} tentative, {heuristic} heuristic)")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
