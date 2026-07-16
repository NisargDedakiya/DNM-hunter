# web_probe — Dynamic HTTP Security Probe

The **dynamic** tier for the VRT rows that are only observable against a running
target. It makes real HTTP requests to a URL and inspects the response — the
"Server Security Misconfiguration", transport, CORS and clickjacking rows a
static source scan can never see.

## What it checks

| Rule | VRT | Sev | Check |
|------|-----|-----|-------|
| WP-HSTS / WP-CSP / WP-XCTO / WP-XFO | `…lack_of_security_headers_*` / `clickjacking_*` | low | Missing security headers (HSTS, CSP, nosniff, frame options) |
| WP-COOKIE-SECURE / HTTPONLY / SAMESITE | `…missing_secure_or_httponly_cookie_flag` / `csrf` | med/low | Insecure `Set-Cookie` flags (session cookies → medium) |
| WP-CORS-WILDCARD-CREDS / WP-CORS-WILDCARD | `…unsafe_cross_origin_resource_sharing` | high/low | Permissive CORS (`*` + credentials is high) |
| WP-METHOD-TRACE / PUT / DELETE / … | `…potentially_unsafe_http_method_enabled` | med | Unsafe methods from the OPTIONS `Allow` header |
| WP-BANNER-SERVER / WP-BANNER-XPB | `…fingerprinting_banner_disclosure` | low | Server/tech version disclosure |
| WP-DIRLIST | `…directory_listing_enabled` | med | Auto-generated directory index |
| WP-DEBUG-PAGE | `…visible_detailed_error_debug_page` | med | Stack trace / framework debug output in the body |
| WP-MIXED | `…mixed_content_https_sourcing_http` | low | HTTPS page loading HTTP sub-resources |
| WP-CLEARTEXT | `insecure_data_transport.cleartext…` | med | Endpoint served over plaintext HTTP |

## Design: testable without a network

`analyze_response(status, headers, body, url, method_allow=…)` is a **pure
function** — all detection logic lives here and is unit-tested with synthetic
responses. `probe_url(url)` is the thin wrapper that performs the GET + OPTIONS
and feeds the analyzer real data. The test suite also spins up a local HTTP
server with deliberately bad headers to exercise the full path end-to-end.

## Scope & ethics

Only GET and OPTIONS are sent — no state-changing or intrusive requests. Point
it at targets you are authorized to test. This covers the *observable-response*
dynamic rows; it does not perform authenticated business-logic testing (IDOR,
session invalidation, OAuth flows) — those remain the job of the platform's
authenticated agent against a live app.

## Usage

```bash
python -m web_probe https://target.example --json
```
