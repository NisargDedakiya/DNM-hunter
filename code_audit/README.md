# code_audit — Web-Application Source SAST

Static detection of the **server-side and web** vulnerability classes that are
visible in source code, mapped to the Bugcrowd VRT. Languages: Python,
JavaScript/TypeScript and **PHP**, with language-agnostic crypto rules.

PHP coverage is taint-aware: sources (`$_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER/
$_FILES`, `php://input`) flow through `$var` assignments into PHP sinks —
`mysqli_query`/`pg_query`/`->prepare` (SQLi), `system`/`shell_exec`/`passthru`
(command injection), `echo`/`print` (reflected XSS, skipped when wrapped in
`htmlspecialchars`/`intval`/…), `include`/`require`/`fopen` (LFI), `curl_exec`/
`file_get_contents` (SSRF) and `eval`/`assert` (RCE). Parameterised
`->prepare("… ?")` and encoded output are **not** flagged.

## What it detects

| Rule | VRT | Sev | Class |
|------|-----|-----|-------|
| CA-SQLI | `server_side_injection.sql_injection` | critical | SQL injection (string-built query) |
| CA-NOSQL | `server_side_injection.nosql_injection` | high | NoSQL / operator injection (`$where`, request object as query) |
| CA-CMDI | `server_side_injection.rce` | critical | OS command injection |
| CA-EVAL | `server_side_injection.rce` | critical | Code-eval sink (`eval`/`exec`/`Function`) |
| CA-DESERIAL | `server_side_injection.rce` | high | Insecure deserialization (pickle/yaml/marshal) |
| CA-LFI | `server_side_injection.file_inclusion_local` | high | Local file inclusion / path traversal |
| CA-SSTI | `server_side_injection.ssti` | high | Server-side template injection |
| CA-XXE | `server_side_injection.xxe` | high | XML external entity |
| CA-LDAP | `server_side_injection.ldap_injection` | high | LDAP injection |
| CA-SSRF | `server_side_injection.ssrf` | high | Server-side request forgery |
| CA-XSS | `cross_site_scripting.stored` | high | XSS sink (`innerHTML`, `document.write`, `res.send`…) |
| CA-CRLF | `server_side_injection.http_response_manipulation` | medium | Response splitting / CRLF |
| CA-REDIR | `unvalidated_redirects.open_redirect` | medium | Open redirect |
| CA-HASH | `cryptographic_weakness.weak_hash` | medium | MD5/SHA1 for security |
| CA-CIPHER | `cryptographic_weakness.broken_cryptography` | high | DES/3DES/RC4/ECB |
| CA-RANDOM | `cryptographic_weakness.insufficient_entropy` | medium | Insecure RNG for a secret |
| CA-RSAKEY | `cryptographic_weakness.insecure_key_generation` | medium | Undersized asymmetric key |
| CA-UPLOAD | `unrestricted_file_upload.arbitrary_file_upload` | high | User-controlled filename/path written to disk |
| CA-IDOR | `broken_access_control.idor` | medium | User id → object lookup (heuristic lead) |
| CA-JWT-NONE | `broken_authentication_and_session_management.jwt_signature_not_verified` | high | JWT `none` algorithm accepted |
| CA-JWT-NOVERIFY | `broken_authentication_and_session_management.jwt_signature_not_verified` | high | JWT signature verification disabled |
| CA-JWT-SECRET | `broken_authentication_and_session_management.weak_jwt_secret` | medium | Hard-coded JWT signing secret |
| CA-CORS | `server_security_misconfiguration.cors_misconfiguration` | medium | Reflected origin, or wildcard + credentials |
| CA-CSRF | `cross_site_request_forgery.application_wide` | medium | CSRF protection disabled / exempted |
| CA-CSV | `external_behavior.csv_injection` | medium | Untrusted data written to a spreadsheet cell (formula injection) |
| CA-DEFAULTCRED | `server_security_misconfiguration.using_default_credentials` | high | Hard-coded / default credentials |
| CA-GRAPHQL | `sensitive_data_exposure.graphql_introspection_enabled` | low | GraphQL introspection / GraphiQL enabled |
| CA-SEED | `cryptographic_weakness.insufficient_entropy` | medium | Predictable PRNG seed |
| CA-IV | `cryptographic_weakness.insufficient_entropy` | medium | Hard-coded / static IV or nonce |
| CA-TOKENURL | `sensitive_data_exposure.sensitive_token_in_url` | low | Secret/token placed in a URL query string |
| CA-MASSASSIGN | `broken_access_control.mass_assignment` | medium | Whole request object bound to a model (BOPLA) |
| CA-PLAINTEXTPW | `sensitive_data_exposure.cleartext_storage_of_password` | medium | Password stored/compared without hashing |
| CA-SWAGGER | `server_security_misconfiguration.api_documentation_exposed` | low | Swagger/OpenAPI/ReDoc explorer exposed |
| CA-DEBUG | `sensitive_data_exposure.debug_page` | medium | Debug mode on |
| CA-TLSVERIFY | `insecure_data_transport.tls_verify_disabled` | medium | TLS verification disabled |
| CA-HTTP | `insecure_data_transport.cleartext` | low | Cleartext HTTP |
| CA-COOKIE | `server_security_misconfiguration.cookie_flags` | low | Missing Secure/HttpOnly |
| CA-WEBSTORE | `insecure_data_storage.web_storage_token` | low | Token in localStorage |

Together these cover the classes hunters ask about most: **SQL injection, XSS,
IDOR, SSRF, authentication/JWT problems, file-upload flaws, API/CORS
misconfiguration, CSRF, default credentials, CSV/formula injection, GraphQL
schema disclosure, weak-randomness (predictable seed / static IV), and secrets
in URLs.** Command injection, LFI/path traversal, SSTI, XXE, insecure
deserialization and the crypto classes round out the server-side set.

### What a source scanner *cannot* do

Many Bugcrowd VRT rows are not decidable from source and are handled by other
tiers of the suite (or are out of scope entirely): live server misconfig,
header/TLS and rate-limiting checks belong to the dynamic scanner (`web_probe`);
network/service issues to `gvm_scan`; secrets to `secret_scanner`; smart
contracts to `contract_audit`; IaC/cloud to `iac_scan`; binaries to
`binary_audit`. Automotive/CAN-bus, physical access, hardware side-channels
(timing/power), and algorithmic/data bias classes require hardware, runtime, or
manual testing and cannot be found by any static scanner. The honest per-row map
of which tier owns each of the ~400 VRT rows lives in `vrt/coverage.py`
(`python -m vrt.coverage --method static`).

## Precision

- **Taint-aware injection.** Sinks (SQLi, RCE, LFI, SSRF, XSS…) fire only when
  attacker-controlled data reaches the argument — directly from a request, or
  through a variable assigned from one. Taint propagates transitively to a
  fixpoint, so a query built on line 5 and executed on line 9 is caught.
- **Parameterisation-aware.** For SQLi/LDAP the query *string* must be assembled
  from input; a bound-parameter call (`execute("… %s", (name,))`) is **not**
  flagged.
- **No literals.** `eval("2+2")`, `open("/etc/config.json")`, `hashlib.sha256(...)`
  do not fire.

## OWASP Top 10 mapping

The suite carries a first-class OWASP coverage map — the **OWASP Top 10 for Web
Applications (2021)** and the **OWASP API Security Top 10 (2023)** — in
`vrt/owasp.py`, queryable with `python -m vrt.owasp` (or `nh-owasp-coverage`).
Each category is honestly tagged by the *tier* that owns it:

| Tier | Meaning |
|------|---------|
| `static` | decidable from source — the CA-* rules are listed |
| `partial` | code_audit surfaces a lead; runtime confirms (e.g. IDOR/BOLA) |
| `dynamic` | only decidable against a live target (`web_probe`/`gvm_scan`) |
| `manual` | business-logic / process review; no scanner decides it |

Where each `code_audit` rule lands:

- **A01 Broken Access Control / API1 BOLA / API5 BFLA** → `CA-IDOR`,
  `CA-MASSASSIGN` (partial — leads; runtime proves the missing check)
- **A02 Cryptographic Failures** → `CA-HASH`, `CA-CIPHER`, `CA-RSAKEY`,
  `CA-SEED`, `CA-IV`, `CA-HTTP`, `CA-TLSVERIFY`, `CA-JWT-SECRET`, `CA-PLAINTEXTPW`
- **A03 Injection** → `CA-SQLI`, `CA-NOSQL`, `CA-CMDI`, `CA-EVAL`, `CA-LDAP`,
  `CA-XXE`, `CA-SSTI`, `CA-CRLF`, `CA-XSS`
- **A05 / API8 Security Misconfiguration** → `CA-DEBUG`, `CA-CORS`, `CA-COOKIE`,
  `CA-DEFAULTCRED`, `CA-GRAPHQL`, `CA-SWAGGER`, `CA-CSRF`
- **A07 / API2 Auth Failures** → `CA-JWT-NONE`, `CA-JWT-NOVERIFY`, `CA-JWT-SECRET`
- **A08 Integrity Failures** → `CA-DESERIAL` (+ `iac_scan` for CI/CD)
- **A10 / API7 SSRF** → `CA-SSRF`, `CA-REDIR`
- **API3 BOPLA** → `CA-MASSASSIGN`

`A04 Insecure Design`, `A06 Vulnerable Components`, `A09 Logging`, `API4/6/9/10`
are **not** source-decidable — they are business-logic, live-target, or
dependency-database problems owned by other tiers or by manual testing. The map
says so plainly rather than pretending otherwise (13/20 categories have static
or partial source coverage).

## Confidence — how exploitable does it look?

Every finding carries a `confidence` field so triage can start with the leads
most likely to be real. It is a **static-evidence** signal, not a runtime proof:

| confidence | meaning | examples |
|------------|---------|----------|
| `firm` | User input provably reaches a dangerous sink with no sanitiser, or a definitive misconfiguration. Likely exploitable. | tainted SQLi/RCE/SSRF sink, JWT `none`/verify-off |
| `tentative` | A risky pattern whose exploitability depends on surrounding context — verify. | hard-coded secret, weak cipher, permissive CORS |
| `heuristic` | A lead that needs manual review; static analysis can't see the missing check. | IDOR (authorization/ownership is invisible to SAST) |

This is how the scanner answers *"is the finding actually exploitable?"* from
source alone. It raises confidence via taint (input → sink, unsanitised) and
flags definitive misconfigurations as `firm`, but it does **not** execute the
target. True runtime confirmation — sending the payload and observing the
response — is the job of the dynamic scanner (`web_probe`) or a manual PoC. The
`confidence` value flows through `repo_scan` and the `scanner_suite`
orchestrator into the SARIF output (`properties.confidence`).

## Honest scope

This is source-pattern + intra-file taint, not whole-program dataflow. It finds
the recognisable, exploitable-looking shapes a reviewer triages first; it does
not prove reachability across files/functions, and it does not confirm
exploitability against a running app (that is the platform's dynamic/runtime
tier). Inter-procedural taint, framework-specific sanitiser awareness, and
non-Python/JS languages are out of scope here.

## Usage

```bash
python -m code_audit path/to/repo --json
```

Also runs automatically inside `repo_scan` (kind `sast`).
