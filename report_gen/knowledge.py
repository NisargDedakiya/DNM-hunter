"""Finding knowledge base — the analyst content that turns a raw detection into
a submission-ready writeup.

For each rule family we curate:
  * a CVSS v3.1 base vector (scored deterministically via common.impact.cvss)
  * how to *verify / reproduce* the issue (what a hunter actually does next)
  * remediation guidance
  * references (CWE / OWASP / SWC / spec links)

Rules without a specific entry fall back to a severity-shaped CVSS vector and
generic-but-honest guidance, so every finding still gets a usable writeup.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Guidance:
    cvss_vector: str
    verification: str
    remediation: str
    references: list[str] = field(default_factory=list)


# CVSS v3.1 base vectors reused below.
_NET_CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"   # 9.8
_NET_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"   # 7.5
_NET_HIGH_INT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"  # 7.5
_NET_HIGH_SCOPE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"  # 8.6
_NET_MED = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"     # 5.4
_NET_MED_UI = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"  # 5.4
_NET_LOW = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"     # 3.1
_LOCAL_HIGH = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"  # 7.8


RULE_KB: dict[str, Guidance] = {
    # ── code_audit — server-side injection ──
    "CA-SQLI": Guidance(
        _NET_CRIT,
        "Submit a payload that alters the query's boolean/structure, e.g. `' OR '1'='1' -- ` in the "
        "affected parameter, and confirm a differential response (auth bypass, extra rows, or a "
        "SQL error). Escalate with UNION/blind-time techniques (sqlmap) to prove data extraction.",
        "Use parameterised queries / prepared statements or an ORM; never build SQL by string "
        "concatenation. Apply least-privilege DB accounts and allow-list input.",
        ["CWE-89", "OWASP A03:2021 Injection", "https://owasp.org/www-community/attacks/SQL_Injection"],
    ),
    "CA-CMDI": Guidance(
        _NET_CRIT,
        "Inject a shell metacharacter payload (`; id`, `| id`, `$(id)`) into the parameter that "
        "reaches the command and confirm command output or an out-of-band callback.",
        "Avoid shelling out; use language-native APIs. If a subprocess is unavoidable, pass an "
        "argument array (never a shell string) and strictly allow-list values.",
        ["CWE-78", "OWASP A03:2021", "https://owasp.org/www-community/attacks/Command_Injection"],
    ),
    "CA-EVAL": Guidance(
        _NET_CRIT,
        "Supply input that evaluates to observable behaviour (e.g. arithmetic that changes output, "
        "or a payload that triggers an error/callback) to prove code execution.",
        "Never pass untrusted data to eval/exec/Function. Parse structured input explicitly; use "
        "safe expression evaluators with a fixed grammar if dynamic evaluation is required.",
        ["CWE-95", "CWE-94", "https://owasp.org/www-community/attacks/Code_Injection"],
    ),
    "CA-DESERIAL": Guidance(
        _NET_CRIT,
        "If you control the serialized blob, craft a gadget payload (e.g. a pickle/`__reduce__` or "
        "Java gadget chain) and confirm code execution or an out-of-band request.",
        "Do not deserialize untrusted data with pickle/marshal/yaml.load/native serializers. Use a "
        "data-only format (JSON) with schema validation, or a safe loader (`yaml.safe_load`).",
        ["CWE-502", "OWASP A08:2021", "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"],
    ),
    "CA-LFI": Guidance(
        _NET_HIGH,
        "Traverse to a known file (`../../../../etc/passwd`, `..\\..\\win.ini`) in the path "
        "parameter and confirm its contents are returned.",
        "Resolve the canonical path and confirm it stays within an allow-listed base directory; "
        "reject `..` and absolute paths; serve by opaque id, not user-supplied path.",
        ["CWE-22", "CWE-98", "https://owasp.org/www-community/attacks/Path_Traversal"],
    ),
    "CA-SSTI": Guidance(
        _NET_CRIT,
        "Inject a template expression for the engine (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`) and "
        "confirm it renders `49`, then escalate to RCE with engine-specific gadgets.",
        "Never render user input as a template. Pass user data as template *variables*, use "
        "auto-escaping, and sandbox the template engine.",
        ["CWE-1336", "CWE-94", "https://portswigger.net/web-security/server-side-template-injection"],
    ),
    "CA-XXE": Guidance(
        _NET_HIGH,
        "Submit XML with an external entity (`<!ENTITY xxe SYSTEM \"file:///etc/passwd\">`) or an "
        "OOB SSRF entity and confirm file read / callback.",
        "Disable external entities and DTDs in the parser (e.g. `resolve_entities=False`, "
        "`FEATURE_SECURE_PROCESSING`); prefer a hardened parser configuration.",
        ["CWE-611", "OWASP A05:2021", "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
    ),
    "CA-LDAP": Guidance(
        _NET_HIGH,
        "Inject LDAP filter metacharacters (`*)(uid=*))(|(uid=*`) and confirm an auth bypass or "
        "broadened result set.",
        "Escape LDAP filter special characters (RFC 4515) or use a parameterised LDAP API; "
        "allow-list input.",
        ["CWE-90", "https://owasp.org/www-community/attacks/LDAP_Injection"],
    ),
    "CA-SSRF": Guidance(
        _NET_HIGH_SCOPE,
        "Point the URL parameter at an internal/metadata endpoint (`http://169.254.169.254/…`, "
        "`http://localhost`) and confirm the server fetches it (response reflected or OOB hit).",
        "Allow-list outbound hosts/schemes; resolve and validate the IP (block link-local/private "
        "ranges); disable redirects to internal targets; use a fetch proxy.",
        ["CWE-918", "OWASP A10:2021", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
    ),
    "CA-XSS": Guidance(
        _NET_MED_UI,
        "Inject `<script>alert(document.domain)</script>` (or an event-handler/`javascript:` "
        "payload) into the reflected/stored sink and confirm script execution in the victim's "
        "context.",
        "Contextually output-encode all untrusted data; prefer safe DOM APIs (`textContent`); add "
        "a strict Content-Security-Policy; avoid `innerHTML`/`dangerouslySetInnerHTML`.",
        ["CWE-79", "OWASP A03:2021", "https://owasp.org/www-community/attacks/xss/"],
    ),
    "CA-CRLF": Guidance(
        _NET_MED,
        "Inject `%0d%0a` sequences into the header/redirect value and confirm an injected header "
        "or split response.",
        "Strip/reject CR and LF from any user data placed into headers; use framework APIs that "
        "encode header values.",
        ["CWE-113", "https://owasp.org/www-community/attacks/HTTP_Response_Splitting"],
    ),
    "CA-REDIR": Guidance(
        _NET_MED_UI,
        "Set the redirect parameter to an external origin (`//evil.example`) and confirm the app "
        "redirects off-site without a warning.",
        "Allow-list redirect targets or use relative paths / indirect ids; show an interstitial "
        "for off-site redirects.",
        ["CWE-601", "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"],
    ),
    # ── code_audit — crypto / config ──
    "CA-HASH": Guidance(
        _NET_MED,
        "Confirm the weak primitive is used for a security purpose (password storage, signatures, "
        "integrity) rather than a non-security checksum.",
        "Use SHA-256+ for integrity and a memory-hard KDF (bcrypt/scrypt/Argon2) for passwords.",
        ["CWE-327", "CWE-916", "https://owasp.org/www-project-cryptographic-storage-cheat-sheet/"],
    ),
    "CA-CIPHER": Guidance(
        _NET_HIGH,
        "Confirm the broken cipher/mode protects sensitive data; demonstrate the weakness "
        "(e.g. ECB pattern leakage, RC4 biases) where feasible.",
        "Use AES-GCM (or ChaCha20-Poly1305) with authenticated encryption; never ECB/DES/RC4.",
        ["CWE-327", "https://owasp.org/www-project-cryptographic-storage-cheat-sheet/"],
    ),
    "CA-RANDOM": Guidance(
        _NET_MED,
        "Confirm the value is security-sensitive (token/OTP/key/nonce) and predictable given the "
        "PRNG state or seed.",
        "Use a CSPRNG (`secrets`, `crypto.randomBytes`, `os.urandom`) for all security values.",
        ["CWE-330", "CWE-338", "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"],
    ),
    # ── contract_audit — smart contracts ──
    "SC-REENTRANCY": Guidance(
        _NET_CRIT,
        "Deploy an attacker contract whose fallback re-enters the vulnerable function during the "
        "external call and confirm repeated withdrawal / drained balance on a fork/testnet.",
        "Apply checks-effects-interactions (update state before the external call) and/or a "
        "`nonReentrant` guard (OpenZeppelin ReentrancyGuard).",
        ["SWC-107", "CWE-841", "https://swcregistry.io/docs/SWC-107"],
    ),
    "SC-DELEGATECALL": Guidance(
        _NET_CRIT,
        "Point the delegatecall target at an attacker contract and confirm it can write this "
        "contract's storage (e.g. overwrite the owner slot) on a testnet.",
        "Never delegatecall a caller-influenced address; use a fixed, audited implementation and "
        "a well-defined storage layout (transparent/UUPS proxy patterns).",
        ["SWC-112", "https://swcregistry.io/docs/SWC-112"],
    ),
    "SC-SELFDESTRUCT": Guidance(
        _NET_HIGH_INT,
        "Call the unguarded function from a non-owner account on a fork and confirm the contract "
        "self-destructs / funds are swept.",
        "Gate selfdestruct behind strict access control (onlyOwner / governance) or remove it.",
        ["SWC-106", "https://swcregistry.io/docs/SWC-106"],
    ),
    "SC-TXORIGIN": Guidance(
        _NET_HIGH,
        "Demonstrate that a malicious intermediary contract, called by the owner, passes the "
        "`tx.origin` check while `msg.sender` differs.",
        "Use `msg.sender` for authorization, never `tx.origin`.",
        ["SWC-115", "https://swcregistry.io/docs/SWC-115"],
    ),
    "SC-UNPROTECTED-OWNER": Guidance(
        _NET_CRIT,
        "Call the privileged setter (setOwner/mint/withdraw/upgrade) from an arbitrary account on "
        "a fork and confirm the state change succeeds.",
        "Add an access-control modifier (onlyOwner / role-based) to every privileged function.",
        ["SWC-105", "https://swcregistry.io/docs/SWC-105"],
    ),
    "SC-OVERFLOW": Guidance(
        _NET_HIGH_INT,
        "On the <0.8 contract, drive an arithmetic operation past its type bound and confirm the "
        "wrapped value (e.g. balance underflow to a huge number).",
        "Compile with Solidity >=0.8 (checked arithmetic) or use SafeMath.",
        ["SWC-101", "https://swcregistry.io/docs/SWC-101"],
    ),
    "SC-UNCHECKED-CALL": Guidance(
        _NET_MED,
        "Force the low-level call to fail (e.g. out-of-gas / reverting recipient) and show the "
        "contract proceeds as if it succeeded.",
        "Check the boolean return of `.call`/`.send`, or use a checked transfer pattern.",
        ["SWC-104", "https://swcregistry.io/docs/SWC-104"],
    ),
    # ── web_probe — dynamic ──
    "WP-CORS-WILDCARD-CREDS": Guidance(
        _NET_HIGH,
        "From an attacker origin, issue a credentialed cross-origin request and confirm the "
        "authenticated response body is readable.",
        "Reflect only allow-listed origins; never combine `Access-Control-Allow-Origin: *` with "
        "`Allow-Credentials: true`.",
        ["CWE-942", "https://developer.mozilla.org/docs/Web/HTTP/CORS"],
    ),
    "WP-COOKIE-HTTPONLY": Guidance(
        _NET_MED,
        "Confirm the session cookie is readable from `document.cookie` (no HttpOnly), enabling "
        "theft via any XSS.",
        "Set `HttpOnly`, `Secure`, and `SameSite` on session cookies.",
        ["CWE-1004", "https://owasp.org/www-community/HttpOnly"],
    ),
}


# Severity-shaped fallback vectors when a rule has no curated entry.
_SEVERITY_FALLBACK = {
    "critical": Guidance(_NET_CRIT, "Reproduce the condition against the target and capture evidence.",
                         "Remediate per the linked reference for this weakness class.", []),
    "high": Guidance(_NET_HIGH, "Reproduce the condition against the target and capture evidence.",
                     "Remediate per the linked reference for this weakness class.", []),
    "medium": Guidance(_NET_MED, "Reproduce the condition and assess exploitability in context.",
                       "Apply the standard control for this weakness class.", []),
    "low": Guidance(_NET_LOW, "Confirm the observation and assess real-world impact.",
                    "Apply defence-in-depth hardening for this class.", []),
    "info": Guidance("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                     "Informational — verify relevance to the engagement scope.",
                     "No direct action required; consider as hardening.", []),
}


def guidance_for(rule_id: str, severity: str) -> Guidance:
    """Look up curated guidance by exact rule id, then by family prefix
    (e.g. 'LLM05:LLM-051' → 'LLM05'), else a severity-shaped fallback."""
    if rule_id in RULE_KB:
        return RULE_KB[rule_id]
    # family: text before ':' (llm/repo_scan composite ids) or a known prefix
    fam = rule_id.split(":", 1)[0]
    if fam in RULE_KB:
        return RULE_KB[fam]
    return _SEVERITY_FALLBACK.get(severity, _SEVERITY_FALLBACK["medium"])
