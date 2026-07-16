# code_audit — Web-Application Source SAST

Static detection of the **server-side and web** vulnerability classes that are
visible in source code, mapped to the Bugcrowd VRT. Languages: Python and
JavaScript/TypeScript, with language-agnostic crypto rules.

## What it detects

| Rule | VRT | Sev | Class |
|------|-----|-----|-------|
| CA-SQLI | `server_side_injection.sql_injection` | critical | SQL injection (string-built query) |
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
| CA-DEBUG | `sensitive_data_exposure.debug_page` | medium | Debug mode on |
| CA-TLSVERIFY | `insecure_data_transport.tls_verify_disabled` | medium | TLS verification disabled |
| CA-HTTP | `insecure_data_transport.cleartext` | low | Cleartext HTTP |
| CA-COOKIE | `server_security_misconfiguration.cookie_flags` | low | Missing Secure/HttpOnly |
| CA-WEBSTORE | `insecure_data_storage.web_storage_token` | low | Token in localStorage |

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
