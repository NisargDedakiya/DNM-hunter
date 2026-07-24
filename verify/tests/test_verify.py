"""Tests for the verification layer.

Each oracle is exercised against a deterministic fake HttpClient that simulates
both a *vulnerable* and a *patched* target, so the confirm/refute/inconclusive
logic is proven without a live target or network. The fakes inspect the raw
request the real oracle produced — the exact production code path runs here.

Run: python -m unittest verify.tests.test_verify -v
"""
import re
import unittest
import urllib.parse

from verify import (
    Candidate,
    DifferentialOracle,
    Identity,
    InMemoryInteractionServer,
    ScopeGuard,
    Verdict,
    VerificationEngine,
    VulnClass,
)
from verify.http import HttpResponse
from verify.oracles import BooleanOracle, ReflectionOracle, TimingOracle


def _raw(req) -> str:
    # A real server decodes '+' in query/body as a space; use unquote_plus so the
    # fakes see the same string the target's framework would.
    return urllib.parse.unquote_plus((req.url or "") + " " + (req.body or ""))


# ── fakes ────────────────────────────────────────────────────────────────────
class TimingFake:
    """Delays the response when a time-based payload is present (if vulnerable)."""
    def __init__(self, vulnerable=True, base_ms=40.0):
        self.vulnerable, self.base_ms = vulnerable, base_ms

    def _delay_s(self, req) -> int:
        s = _raw(req)
        m = (re.search(r"(?:SLEEP|pg_sleep)\((\d+)", s, re.I)
             or re.search(r"WAITFOR DELAY '0:0:(\d+)'", s, re.I)
             or re.search(r"\bsleep (\d+)", s, re.I))
        return int(m.group(1)) if m else 0

    def send(self, req):
        d = self._delay_s(req) if self.vulnerable else 0
        return HttpResponse(200, {}, "ok", self.base_ms + d * 1000.0)


class BooleanFake:
    """Returns baseline for TRUE conditions and a divergent body for FALSE (if vulnerable)."""
    def __init__(self, vulnerable=True):
        self.vulnerable = vulnerable

    def send(self, req):
        s = _raw(req)
        if self.vulnerable and re.search(r"AND '1'='2", s):
            return HttpResponse(200, {}, "RESULTS:")            # FALSE → empty result set
        return HttpResponse(200, {}, "RESULTS: alice bob carol")  # baseline / TRUE


class ReflectionFake:
    """Echoes the injected marker raw / encoded / not-at-all."""
    def __init__(self, mode="raw"):
        self.mode = mode  # "raw" | "encoded" | "absent"

    def send(self, req):
        m = re.search(r"<(dnmh[0-9a-f]+)>", _raw(req))
        if not m or self.mode == "absent":
            return HttpResponse(200, {}, "<html>nothing reflected</html>")
        tok = m.group(1)
        if self.mode == "raw":
            return HttpResponse(200, {}, f"<html>hi <{tok}> there</html>")
        return HttpResponse(200, {}, f"<html>hi &lt;{tok}&gt; there</html>")


class OastFake:
    """Fires the OAST callback when it sees the callback domain (if vulnerable)."""
    def __init__(self, server, vulnerable=True):
        self.server, self.vulnerable = server, vulnerable

    def send(self, req):
        if self.vulnerable:
            m = re.search(r"([0-9a-f]+\.oast\.local)", _raw(req))
            if m:
                self.server.trigger(m.group(1), protocol="http", remote_addr="10.0.0.5")
        return HttpResponse(200, {}, "ok")


class AuthzFake:
    """Owner always gets the record; others get it too (vulnerable) or 403 (patched)."""
    def __init__(self, vulnerable=True):
        self.vulnerable = vulnerable

    def send(self, req):
        who = req.headers.get("X-User", "")
        if who == "owner" or self.vulnerable:
            return HttpResponse(200, {}, "SSN=123-45-6789 owner=alice")
        return HttpResponse(403, {}, "forbidden")


class RateLimitFake:
    """Accepts every submission (vulnerable), or starts returning 429 after `limit`
    requests (patched — rate limiting present)."""
    def __init__(self, limit=None):
        self.limit = limit
        self.count = 0

    def send(self, req):
        self.count += 1
        if self.limit is not None and self.count > self.limit:
            return HttpResponse(429, {}, "Too Many Requests — rate limit exceeded")
        return HttpResponse(200, {}, "Thanks, your message was sent.")


class EmailHeaderFake:
    """A contact form. Vulnerable: a Bcc-injecting CRLF payload triggers an
    out-of-band mail delivery. Validating: rejects any CRLF with a 400."""
    def __init__(self, server=None, vulnerable=True, validating=False):
        self.server, self.vulnerable, self.validating = server, vulnerable, validating

    def send(self, req):
        raw = urllib.parse.unquote_plus(req.body or "")   # decode as a framework would
        has_crlf = ("\r\n" in raw or "\n" in raw)          # a *real* header break
        if has_crlf and self.validating:
            return HttpResponse(400, {}, "Invalid characters in input")
        # Only a genuine CRLF actually breaks into a new header and delivers mail.
        if has_crlf and self.vulnerable and self.server:
            m = re.search(r"(c[0-9a-f]+)@([0-9a-f]+\.oast\.local)", raw)
            if m:
                self.server.trigger(m.group(1), protocol="smtp", remote_addr="10.0.0.7")
        return HttpResponse(200, {}, "Thanks, your message was sent.")


SCOPE = ScopeGuard({"staging.example.com"})
URL = "https://staging.example.com/item"
CONTACT = "https://staging.example.com/contact"


# ── timing oracle ────────────────────────────────────────────────────────────
class TestTimingOracle(unittest.TestCase):
    def test_confirms_time_based_sqli(self):
        r = TimingOracle(delay_s=3.0, trials=2).verify(
            Candidate(VulnClass.BLIND_SQLI, URL, param="id", base_value="1"), TimingFake(True))
        self.assertEqual(r.verdict, Verdict.CONFIRMED)
        self.assertEqual(r.oracle, "timing")
        self.assertTrue(r.evidence)

    def test_inconclusive_when_no_delay(self):
        r = TimingOracle(delay_s=3.0, trials=2).verify(
            Candidate(VulnClass.BLIND_SQLI, URL, param="id", base_value="1"), TimingFake(False))
        self.assertEqual(r.verdict, Verdict.INCONCLUSIVE)


# ── boolean oracle ───────────────────────────────────────────────────────────
class TestBooleanOracle(unittest.TestCase):
    def test_confirms_boolean_blind(self):
        r = BooleanOracle().verify(
            Candidate(VulnClass.BOOLEAN_SQLI, URL, param="id", base_value="1"), BooleanFake(True))
        self.assertEqual(r.verdict, Verdict.CONFIRMED)

    def test_inconclusive_when_stable(self):
        r = BooleanOracle().verify(
            Candidate(VulnClass.BOOLEAN_SQLI, URL, param="id", base_value="1"), BooleanFake(False))
        self.assertEqual(r.verdict, Verdict.INCONCLUSIVE)


# ── reflection oracle ────────────────────────────────────────────────────────
class TestReflectionOracle(unittest.TestCase):
    def test_confirms_raw_reflection(self):
        r = ReflectionOracle().verify(
            Candidate(VulnClass.REFLECTED_XSS, URL, param="q"), ReflectionFake("raw"))
        self.assertEqual(r.verdict, Verdict.CONFIRMED)

    def test_refutes_encoded_reflection(self):
        r = ReflectionOracle().verify(
            Candidate(VulnClass.REFLECTED_XSS, URL, param="q"), ReflectionFake("encoded"))
        self.assertEqual(r.verdict, Verdict.REFUTED)

    def test_inconclusive_when_absent(self):
        r = ReflectionOracle().verify(
            Candidate(VulnClass.REFLECTED_XSS, URL, param="q"), ReflectionFake("absent"))
        self.assertEqual(r.verdict, Verdict.INCONCLUSIVE)


# ── rate-limit oracle (form abuse) ───────────────────────────────────────────
class TestRateLimitOracle(unittest.TestCase):
    def test_confirms_no_rate_limiting(self):
        from verify.oracles import RateLimitOracle
        c = Candidate(VulnClass.FORM_ABUSE, CONTACT, method="POST", param="", param_in="body",
                      form_fields={"email": "a@b.c", "message": "hi"})
        r = RateLimitOracle(burst=8).verify(c, RateLimitFake(limit=None))
        self.assertEqual(r.verdict, Verdict.CONFIRMED)
        self.assertEqual(r.oracle, "rate-limit")

    def test_refutes_when_throttled(self):
        from verify.oracles import RateLimitOracle
        c = Candidate(VulnClass.FORM_ABUSE, CONTACT, method="POST", param="", param_in="body")
        r = RateLimitOracle(burst=8).verify(c, RateLimitFake(limit=3))   # 429 after 3
        self.assertEqual(r.verdict, Verdict.REFUTED)

    def test_engine_routes_form_abuse(self):
        engine = VerificationEngine(SCOPE, client=RateLimitFake(limit=None))
        r = engine.verify(Candidate(VulnClass.FORM_ABUSE, CONTACT, method="POST", param_in="body"))
        self.assertEqual(r.verdict, Verdict.CONFIRMED)


# ── email header injection oracle ────────────────────────────────────────────
class TestEmailHeaderInjectionOracle(unittest.TestCase):
    def test_confirms_via_out_of_band_delivery(self):
        server = InMemoryInteractionServer()
        engine = VerificationEngine(SCOPE, client=EmailHeaderFake(server, vulnerable=True),
                                    interaction_server=server)
        r = engine.verify(Candidate(VulnClass.EMAIL_HEADER_INJECTION, CONTACT, method="POST",
                                    param="email", param_in="body", base_value="a@b.c"))
        self.assertEqual(r.verdict, Verdict.CONFIRMED)
        self.assertEqual(r.confidence, 1.0)
        self.assertEqual(r.evidence[0].kind, "oob-interaction")

    def test_refutes_when_crlf_rejected(self):
        server = InMemoryInteractionServer()
        engine = VerificationEngine(SCOPE, client=EmailHeaderFake(server, validating=True),
                                    interaction_server=server)
        r = engine.verify(Candidate(VulnClass.EMAIL_HEADER_INJECTION, CONTACT, method="POST",
                                    param="email", param_in="body", base_value="a@b.c"))
        self.assertEqual(r.verdict, Verdict.REFUTED)

    def test_inconclusive_when_accepted_without_oob(self):
        # no interaction server → can't confirm out-of-band; accepted silently → lead
        engine = VerificationEngine(SCOPE, client=EmailHeaderFake(None, vulnerable=False))
        r = engine.verify(Candidate(VulnClass.EMAIL_HEADER_INJECTION, CONTACT, method="POST",
                                    param="email", param_in="body", base_value="a@b.c"))
        self.assertEqual(r.verdict, Verdict.INCONCLUSIVE)


# ── OAST oracle (via engine, since it needs a server) ────────────────────────
class TestOastOracle(unittest.TestCase):
    def test_confirms_ssrf_via_callback(self):
        server = InMemoryInteractionServer()
        engine = VerificationEngine(SCOPE, client=OastFake(server, True), interaction_server=server)
        r = engine.verify(Candidate(VulnClass.SSRF, URL, param="url", base_value="http://x"))
        self.assertEqual(r.verdict, Verdict.CONFIRMED)
        self.assertEqual(r.confidence, 1.0)          # out-of-band proof is definitive
        self.assertEqual(r.evidence[0].kind, "oob-interaction")

    def test_inconclusive_without_callback(self):
        server = InMemoryInteractionServer()
        engine = VerificationEngine(SCOPE, client=OastFake(server, False), interaction_server=server)
        r = engine.verify(Candidate(VulnClass.SSRF, URL, param="url"))
        self.assertEqual(r.verdict, Verdict.INCONCLUSIVE)

    def test_ssrf_skipped_without_server(self):
        engine = VerificationEngine(SCOPE, client=OastFake(InMemoryInteractionServer(), True))
        r = engine.verify(Candidate(VulnClass.SSRF, URL, param="url"))
        self.assertEqual(r.verdict, Verdict.SKIPPED)


# ── differential oracle (IDOR / BOLA) ────────────────────────────────────────
class TestDifferentialOracle(unittest.TestCase):
    def _cand(self):
        return Candidate(
            VulnClass.IDOR, URL, param="id", base_value="42",
            identities=[Identity("owner", {"X-User": "owner"}, authorized=True),
                        Identity("attacker", {"X-User": "attacker"}, authorized=False)],
            owner_marker="SSN=123-45-6789")

    def test_confirms_idor_when_marker_leaks(self):
        r = DifferentialOracle().verify(self._cand(), AuthzFake(vulnerable=True))
        self.assertEqual(r.verdict, Verdict.CONFIRMED)
        self.assertIn("unauthorised", r.note.lower())

    def test_refutes_when_denied(self):
        r = DifferentialOracle().verify(self._cand(), AuthzFake(vulnerable=False))
        self.assertEqual(r.verdict, Verdict.REFUTED)

    def test_inconclusive_without_two_identities(self):
        c = self._cand()
        c.identities = [Identity("owner", {"X-User": "owner"}, authorized=True)]
        r = DifferentialOracle().verify(c, AuthzFake(True))
        self.assertEqual(r.verdict, Verdict.INCONCLUSIVE)


# ── scope gate (the legal boundary) ──────────────────────────────────────────
class TestScopeGate(unittest.TestCase):
    def test_out_of_scope_is_skipped_never_tested(self):
        # A fake that would explode if actually called — proves the gate blocks first.
        class Boom:
            def send(self, req):
                raise AssertionError("out-of-scope target must never be contacted")
        engine = VerificationEngine(ScopeGuard({"authorised.example.com"}), client=Boom(),
                                    interaction_server=InMemoryInteractionServer())
        r = engine.verify(Candidate(VulnClass.SSRF, "https://evil.example.org/x", param="url"))
        self.assertEqual(r.verdict, Verdict.SKIPPED)
        self.assertIn("scope", r.oracle)

    def test_empty_scope_authorises_nothing(self):
        self.assertFalse(ScopeGuard(set()).is_allowed("https://anything.com"))

    def test_subdomain_scope(self):
        g = ScopeGuard({"example.com"}, allow_subdomains=True)
        self.assertTrue(g.is_allowed("https://api.example.com/x"))
        self.assertFalse(g.is_allowed("https://example.org/x"))


# ── engine routing / aggregation ─────────────────────────────────────────────
class TestEngine(unittest.TestCase):
    def test_blind_sqli_falls_back_to_boolean(self):
        # Timing fake shows no delay, but boolean signal is present → boolean confirms.
        class Combo:
            def send(self, req):
                s = _raw(req)
                if re.search(r"AND '1'='2", s):
                    return HttpResponse(200, {}, "RESULTS:")
                return HttpResponse(200, {}, "RESULTS: alice bob")
        engine = VerificationEngine(SCOPE, client=Combo())
        r = engine.verify(Candidate(VulnClass.BLIND_SQLI, URL, param="id", base_value="1"))
        self.assertEqual(r.verdict, Verdict.CONFIRMED)
        self.assertEqual(r.oracle, "boolean")

    def test_unknown_class_skipped(self):
        engine = VerificationEngine(SCOPE, client=TimingFake())
        c = Candidate("totally_unknown", URL, param="x")
        self.assertEqual(engine.verify(c).verdict, Verdict.SKIPPED)

    def test_result_serialises(self):
        engine = VerificationEngine(SCOPE, client=TimingFake(True))
        r = engine.verify(Candidate(VulnClass.BLIND_SQLI, URL, param="id", base_value="1",
                                    source_rule="CA-SQLI"))
        d = r.to_dict()
        self.assertEqual(d["verdict"], "confirmed")
        self.assertEqual(d["source_rule"], "CA-SQLI")
        self.assertIn("evidence", d)


if __name__ == "__main__":
    unittest.main()
