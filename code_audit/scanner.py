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
from dataclasses import dataclass, asdict
from pathlib import Path

CRIT, HIGH, MED, LOW, INFO = "critical", "high", "medium", "low", "info"

_SRC_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
_SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".next",
              "__pycache__", ".venv", "venv", "site-packages", "migrations"}

# ── user-input taint sources (Python + JS/TS web frameworks) ──
_USER_INPUT = re.compile(
    r"(request\.(args|form|values|json|data|files|GET|POST|body|query|params|cookies|headers)"
    r"|req\.(body|query|params|cookies|headers)"
    r"|\.args\.get|\.get_json|flask\.request|self\.get_argument"
    r"|params\[|query\[|body\[|\$_(GET|POST|REQUEST|COOKIE)"
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
    ("cryptographic_weakness.insufficient_entropy", "CA-RANDOM", MED, "CWE-330",
     "Insecure RNG used for a security value (use a CSPRNG)",
     re.compile(r"\b(random\.(random|randint|randrange|choice|getrandbits|sample|shuffle)|Math\.random|mt_rand|rand\s*\()", re.IGNORECASE)),
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
]


# Sinks where the *query string itself* is assembled from input — flagging must
# be parameterisation-aware (a bound-parameter query is safe even with taint).
_QUERY_SINKS = {"CA-SQLI", "CA-LDAP"}

_ASSIGN_RE = re.compile(r"\s*(?:(?:const|let|var)\s+)?([A-Za-z_]\w*)\s*=\s*([^=].*)$")


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
        or re.search(r"['\"]\s*%\s*[\(\w]", rhs))    # "..." % (x)  (operator, not %s)


def _is_query_build(rhs: str, tainted: set[str]) -> bool:
    has_str = "'" in rhs or '"' in rhs or "`" in rhs
    return has_str and _string_interp(rhs) and (bool(_USER_INPUT.search(rhs)) or _refs(rhs, tainted))


def _looks_literal_only(arg_region: str) -> bool:
    """The sink is called on a single string/number literal — not user data."""
    return bool(re.match(r"\s*\(\s*(?:[rbf]?['\"][^'\"]*['\"]|\d+)\s*[,)]", arg_region))


def scan_code(text: str, file: str) -> list[CodeFinding]:
    findings: list[CodeFinding] = []
    lines = text.splitlines()
    is_py = file.endswith(".py")

    def add(vrt, rule, sev, title, i, detail, cwe=""):
        findings.append(CodeFinding(vrt, rule, sev, title, file, i, detail, cwe))

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
                tainted.add(var); changed = True
            if _is_query_build(rhs, tainted) and var not in sql_risky:
                sql_risky.add(var); changed = True
        if not changed:
            break

    for i, raw in enumerate(lines, 1):
        line = raw.split("#", 1)[0] if is_py else raw
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "*", "/*")):
            continue

        # taint-sensitive injection sinks
        for vrt, rule, sev, cwe, title, sink_rx in _TAINT_SINKS:
            m = sink_rx.search(line)
            if not m:
                continue
            arg_region = line[m.end() - 1:]  # from the "(" onward
            if _looks_literal_only(arg_region):
                continue
            if rule in _QUERY_SINKS:
                # only a string built from input is injectable; bound params are safe
                hit = _is_query_build(arg_region, tainted) or _refs(arg_region, sql_risky)
            else:
                # value sinks: dangerous whenever attacker data reaches the argument
                hit = bool(_USER_INPUT.search(arg_region)) or _refs(arg_region, tainted)
            if hit:
                add(vrt, rule, sev, title, i,
                    f"{title}. Untrusted data reaches this sink — use parameterisation / "
                    f"safe APIs / validation & output encoding.", cwe)

        # context-free static rules
        for vrt, rule, sev, cwe, title, rx in _STATIC_RULES:
            if rx.search(line):
                add(vrt, rule, sev, title, i, f"{title}.", cwe)

    return findings


def scan_tree(root: str | Path) -> list[CodeFinding]:
    root = Path(root)
    out: list[CodeFinding] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _SRC_EXT:
            continue
        if any(p in _SKIP_DIRS for p in path.parts):
            continue
        try:
            text = path.read_text(errors="replace")
        except Exception:
            continue
        out.extend(scan_code(text, str(path.relative_to(root))))
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
    for f in sorted(findings, key=lambda x: x.severity):
        print(f"  [{f.severity:8}] {f.rule_id:12} {f.file}:{f.line}  {f.title}")
    print(f"\n{len(findings)} findings")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
