"""Dynamic live-HTTP security scanner — the VRT rows that are only observable
against a running target.

Unlike the static analysers, this makes real HTTP requests to a URL and inspects
the response: missing/weak security headers, insecure cookie flags, permissive
CORS, unsafe HTTP methods, clickjacking exposure, server/tech banner disclosure,
directory listing, verbose error/debug pages, and mixed content. These are the
"Server Security Misconfiguration" and related dynamic VRT rows that a source
scan cannot see.

The analysis is split so it is fully testable without network access:
`analyze_response(...)` is a pure function over (status, headers, body, url);
`probe_url(url)` is the thin network wrapper that feeds it real responses.

CLI:  python -m web_probe https://target.example [--json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

CRIT, HIGH, MED, LOW, INFO = "critical", "high", "medium", "low", "info"


@dataclass
class WebFinding:
    vrt: str
    rule_id: str
    severity: str
    title: str
    url: str
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


def _hget(headers: dict, name: str) -> str | None:
    """Case-insensitive header lookup returning the first match."""
    low = name.lower()
    for k, v in headers.items():
        if k.lower() == low:
            return v
    return None


def _all_set_cookies(headers: dict) -> list[str]:
    out = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            out.append(v)
    return out


# security headers whose ABSENCE is a finding: (header, vrt, rule, sev, title)
_MISSING_HEADER_RULES = [
    ("Strict-Transport-Security", "server_security_misconfiguration.lack_of_security_headers_strict_transport_security",
     "WP-HSTS", LOW, "Missing Strict-Transport-Security (HSTS) header"),
    ("Content-Security-Policy", "server_security_misconfiguration.lack_of_security_headers_content_security_policy",
     "WP-CSP", LOW, "Missing Content-Security-Policy header"),
    ("X-Content-Type-Options", "server_security_misconfiguration.lack_of_security_headers_x_content_type_options",
     "WP-XCTO", LOW, "Missing X-Content-Type-Options: nosniff header"),
    ("X-Frame-Options", "server_security_misconfiguration.clickjacking_non_sensitive_action",
     "WP-XFO", LOW, "Missing X-Frame-Options / frame-ancestors (clickjacking exposure)"),
]


def analyze_response(status: int, headers: dict, body: str, url: str,
                     method_allow: str | None = None) -> list[WebFinding]:
    """Pure analysis of one HTTP response. `method_allow` is the Allow header
    from an OPTIONS request, if the caller performed one."""
    findings: list[WebFinding] = []
    is_https = urlparse(url).scheme == "https"

    def add(vrt, rule, sev, title, detail):
        findings.append(WebFinding(vrt, rule, sev, title, url, detail))

    # ── missing security headers ──
    for header, vrt, rule, sev, title in _MISSING_HEADER_RULES:
        if _hget(headers, header) is None:
            # HSTS only meaningful over https
            if rule == "WP-HSTS" and not is_https:
                continue
            add(vrt, rule, sev, title, f"Response did not set '{header}'.")

    # frame-ancestors in CSP satisfies clickjacking protection even without XFO
    csp = _hget(headers, "Content-Security-Policy") or ""
    if _hget(headers, "X-Frame-Options") is None and "frame-ancestors" in csp.lower():
        findings = [f for f in findings if f.rule_id != "WP-XFO"]

    # ── cookie flags ──
    for cookie in _all_set_cookies(headers):
        cl = cookie.lower()
        cname = cookie.split("=", 1)[0].strip()
        looks_session = bool(re.search(r"(sess|sid|auth|token|jwt|login)", cname, re.IGNORECASE))
        sev = MED if looks_session else LOW
        if "secure" not in cl and is_https:
            add("server_security_misconfiguration.missing_secure_or_httponly_cookie_flag_session_token",
                "WP-COOKIE-SECURE", sev, f"Cookie '{cname}' missing Secure flag",
                "Cookie set over HTTPS without the Secure attribute — it can leak over plaintext.")
        if "httponly" not in cl:
            add("server_security_misconfiguration.missing_secure_or_httponly_cookie_flag_session_token",
                "WP-COOKIE-HTTPONLY", sev, f"Cookie '{cname}' missing HttpOnly flag",
                "Cookie readable from JavaScript (no HttpOnly) — exploitable via XSS.")
        if "samesite" not in cl:
            add("cross_site_request_forgery.application_wide",
                "WP-COOKIE-SAMESITE", LOW, f"Cookie '{cname}' missing SameSite attribute",
                "No SameSite attribute — the cookie is sent on cross-site requests (CSRF surface).")

    # ── permissive CORS ──
    acao = _hget(headers, "Access-Control-Allow-Origin")
    acac = (_hget(headers, "Access-Control-Allow-Credentials") or "").lower()
    if acao == "*" and acac == "true":
        add("server_security_misconfiguration.unsafe_cross_origin_resource_sharing",
            "WP-CORS-WILDCARD-CREDS", HIGH, "CORS allows any origin with credentials",
            "Access-Control-Allow-Origin: * together with Allow-Credentials: true lets any "
            "site read authenticated responses.")
    elif acao == "*":
        add("server_security_misconfiguration.unsafe_cross_origin_resource_sharing",
            "WP-CORS-WILDCARD", LOW, "CORS allows any origin (wildcard)",
            "Access-Control-Allow-Origin: * — acceptable only for truly public data.")

    # ── unsafe HTTP methods (from an OPTIONS Allow header) ──
    if method_allow:
        allowed = {m.strip().upper() for m in method_allow.split(",")}
        for meth, sev in (("TRACE", MED), ("TRACK", MED), ("PUT", MED), ("DELETE", MED), ("CONNECT", MED)):
            if meth in allowed:
                add("server_security_misconfiguration.potentially_unsafe_http_method_enabled_trace",
                    f"WP-METHOD-{meth}", sev, f"Potentially unsafe HTTP method enabled: {meth}",
                    f"The server advertises {meth} in its Allow header.")

    # ── banner / tech disclosure ──
    server = _hget(headers, "Server")
    if server and re.search(r"\d", server):
        add("server_security_misconfiguration.fingerprinting_banner_disclosure",
            "WP-BANNER-SERVER", LOW, "Server version disclosed in banner",
            f"Server header reveals software/version: '{server}'.")
    xpb = _hget(headers, "X-Powered-By")
    if xpb:
        add("server_security_misconfiguration.fingerprinting_banner_disclosure",
            "WP-BANNER-XPB", LOW, "Technology stack disclosed via X-Powered-By",
            f"X-Powered-By header reveals: '{xpb}'.")

    # ── directory listing ──
    if re.search(r"<title>\s*Index of /|Directory listing for /", body, re.IGNORECASE):
        add("server_security_misconfiguration.directory_listing_enabled_sensitive_data_exposure",
            "WP-DIRLIST", MED, "Directory listing enabled",
            "The server returned an auto-generated directory index.")

    # ── verbose error / debug page ──
    if re.search(r"(Traceback \(most recent call last\)|Whitespace at|Werkzeug Debugger|"
                 r"Exception at /|\.java:\d+\)|ORA-\d{5}|SQLSTATE\[|Warning: .* on line \d+|"
                 r"Stack trace:|System\.\w+Exception)", body):
        add("sensitive_data_exposure.visible_detailed_error_debug_page_descriptive_stack_trace",
            "WP-DEBUG-PAGE", MED, "Verbose error / debug page exposed",
            "The response body contains a stack trace or framework debug output.")

    # ── mixed content ──
    if is_https and re.search(r"""(?:src|href)\s*=\s*['"]http://(?!localhost|127\.0\.0\.1)""", body, re.IGNORECASE):
        add("sensitive_data_exposure.mixed_content_https_sourcing_http",
            "WP-MIXED", LOW, "Mixed content (HTTPS page sourcing HTTP)",
            "An HTTPS page references sub-resources over plaintext HTTP.")

    # ── cleartext transport ──
    if not is_https:
        add("insecure_data_transport.cleartext_transmission_of_sensitive_data",
            "WP-CLEARTEXT", MED, "Service served over cleartext HTTP",
            "The endpoint is reachable over HTTP without TLS.")

    return findings


def probe_url(url: str, timeout: float = 15.0) -> list[WebFinding]:
    """Fetch `url` (and an OPTIONS request for method discovery) and analyse it.
    Network errors are returned as an INFO finding rather than raised."""
    import urllib.request
    import urllib.error

    headers: dict[str, str] = {}
    body = ""
    status = 0
    method_allow = None

    req = urllib.request.Request(url, headers={"User-Agent": "NisargHunter-web_probe/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            headers = {k: v for k, v in resp.headers.items()}
            body = resp.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status = e.code
        headers = {k: v for k, v in (e.headers.items() if e.headers else [])}
        try:
            body = e.read(200_000).decode("utf-8", "replace")
        except Exception:
            body = ""
    except Exception as exc:
        return [WebFinding("", "WP-ERROR", INFO, "Target unreachable", url,
                           f"{type(exc).__name__}: {exc}")]

    # OPTIONS for method discovery (best effort)
    try:
        oreq = urllib.request.Request(url, method="OPTIONS",
                                      headers={"User-Agent": "NisargHunter-web_probe/1.0"})
        with urllib.request.urlopen(oreq, timeout=timeout) as oresp:
            method_allow = oresp.headers.get("Allow")
    except Exception:
        pass

    return analyze_response(status, headers, body, url, method_allow=method_allow)


def _main() -> int:
    ap = argparse.ArgumentParser(description="Dynamic live-HTTP security scanner (VRT-mapped).")
    ap.add_argument("url")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    findings = probe_url(args.url)
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
        return 0
    for f in sorted(findings, key=lambda x: x.severity):
        print(f"  [{f.severity:8}] {f.rule_id:22} {f.title}")
    print(f"\n{len(findings)} findings for {args.url}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
