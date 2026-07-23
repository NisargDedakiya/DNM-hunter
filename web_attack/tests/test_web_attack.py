"""Tests for the active web-injection engine.

A deterministic in-memory `VulnApp` simulates a small vulnerable site:
  /search?q=  → reflects input raw          (reflected XSS)
  /item?id=   → SLEEP() delays the response (time-based blind SQLi)
  /fetch?url= → fetches the given URL       (SSRF, out-of-band)
  /login      → a normal form, not injectable (false-positive guard)

The real crawler + candidate generator + verification oracles run end-to-end
against it, offline. This is the proof the engine finds injections that a passive
header scanner walks right past.

Run: python -m unittest web_attack.tests.test_web_attack -v
"""
import re
import unittest
from urllib.parse import parse_qsl, urlsplit

from verify import InMemoryInteractionServer, ScopeGuard, VulnClass
from verify.http import HttpResponse
from verify.oracles import TimingOracle
from web_attack import WebAttackEngine, candidates_for
from web_attack.crawl import Crawler, InjectionPoint
from web_attack.engine import _is_url_param

_INDEX = """<html><body>
  <a href="/search?q=hello">search</a>
  <a href="/item?id=1">item</a>
  <a href="/fetch?url=http://internal/health">fetch</a>
  <a href="https://evil.example.org/x?p=1">offsite</a>
  <form action="/login" method="post">
    <input name="user" value="">
    <input name="pass" type="password">
    <input type="submit" value="go">
  </form>
</body></html>"""


class VulnApp:
    """A deliberately vulnerable simulated app (offline)."""

    def __init__(self, server: InMemoryInteractionServer):
        self.server = server
        self.hits: list[str] = []

    def send(self, req):
        self.hits.append(req.url)
        parts = urlsplit(req.url)
        path = parts.path or "/"
        q = dict(parse_qsl(parts.query, keep_blank_values=True))
        if req.body:
            q.update(dict(parse_qsl(req.body, keep_blank_values=True)))

        if path in ("/", ""):
            return HttpResponse(200, {}, _INDEX, 30.0)
        if path == "/search":                       # reflected XSS — raw echo
            return HttpResponse(200, {}, f"<h1>Results for {q.get('q','')}</h1>", 30.0)
        if path == "/item":                         # time-based blind SQLi
            m = (re.search(r"SLEEP\((\d+)", q.get("id", ""), re.I)
                 or re.search(r"pg_sleep\((\d+)", q.get("id", ""), re.I)
                 or re.search(r"WAITFOR DELAY '0:0:(\d+)'", q.get("id", ""), re.I))
            d = int(m.group(1)) if m else 0
            return HttpResponse(200, {}, "item detail", 30.0 + d * 1000.0)
        if path == "/fetch":                        # SSRF — fetches the URL
            mm = re.search(r"([0-9a-f]+\.oast\.local)", q.get("url", ""))
            if mm:
                self.server.trigger(mm.group(1), "http", "10.0.0.9")
            return HttpResponse(200, {}, "fetched", 30.0)
        if path == "/login":                        # not injectable
            return HttpResponse(200, {}, "welcome", 30.0)
        return HttpResponse(404, {}, "not found", 10.0)


SCOPE = ScopeGuard({"app.test"})
SEED = "https://app.test/"


def _engine():
    server = InMemoryInteractionServer()
    app = VulnApp(server)
    engine = WebAttackEngine(SCOPE, client=app, interaction_server=server,
                             timing=TimingOracle(delay_s=3.0, trials=1))
    return engine, app


# ── crawl / surface discovery ────────────────────────────────────────────────
class TestCrawl(unittest.TestCase):
    def test_discovers_params_and_form_fields(self):
        server = InMemoryInteractionServer()
        surface = Crawler(VulnApp(server), SCOPE).crawl(SEED)
        params = {p.param for p in surface.points}
        self.assertIn("q", params)      # from /search link
        self.assertIn("id", params)     # from /item link
        self.assertIn("url", params)    # from /fetch link
        self.assertIn("user", params)   # from the login form
        self.assertIn("pass", params)

    def test_stays_in_scope(self):
        server = InMemoryInteractionServer()
        surface = Crawler(VulnApp(server), SCOPE).crawl(SEED)
        # The offsite evil.example.org link must never become an injection point.
        self.assertFalse(any("evil.example.org" in p.url for p in surface.points))
        self.assertFalse(any("evil.example.org" in page for page in surface.pages))

    def test_form_field_is_body_post(self):
        server = InMemoryInteractionServer()
        surface = Crawler(VulnApp(server), SCOPE).crawl(SEED)
        user = [p for p in surface.points if p.param == "user"][0]
        self.assertEqual(user.method, "POST")
        self.assertEqual(user.param_in, "body")


# ── candidate generation ─────────────────────────────────────────────────────
class TestCandidates(unittest.TestCase):
    def test_ssrf_only_for_url_params(self):
        self.assertTrue(_is_url_param("redirect_url"))
        self.assertFalse(_is_url_param("comment"))
        pt = InjectionPoint("https://app.test/x", "comment", "query", "GET")
        classes = {c.vuln_class for c in candidates_for(pt, [VulnClass.SSRF, VulnClass.REFLECTED_XSS])}
        self.assertNotIn(VulnClass.SSRF, classes)      # no URL hint → no SSRF candidate
        self.assertIn(VulnClass.REFLECTED_XSS, classes)


# ── full engine: finds the real injections ───────────────────────────────────
class TestEngineFindsInjections(unittest.TestCase):
    def test_confirms_xss_sqli_ssrf(self):
        engine, _ = _engine()
        report = engine.run(SEED)
        found = {(f.title, f.param) for f in report.findings}
        self.assertIn(("Reflected cross-site scripting", "q"), found)
        self.assertIn(("SQL injection", "id"), found)
        self.assertIn(("Server-side request forgery", "url"), found)

    def test_ssrf_finding_is_out_of_band_confident(self):
        engine, _ = _engine()
        report = engine.run(SEED)
        ssrf = [f for f in report.findings if f.param == "url"][0]
        self.assertEqual(ssrf.oracle, "oast")
        self.assertEqual(ssrf.confidence, 1.0)

    def test_no_false_positive_on_clean_login(self):
        engine, _ = _engine()
        report = engine.run(SEED)
        self.assertFalse(any(f.param in ("user", "pass") for f in report.findings))

    def test_report_serialises_and_counts(self):
        engine, _ = _engine()
        report = engine.run(SEED)
        d = report.to_dict()
        self.assertGreaterEqual(d["injection_points"], 5)
        self.assertGreaterEqual(d["summary"]["confirmed"], 3)
        self.assertEqual(d["summary"]["confirmed"], len(d["findings"]))


# ── scope enforcement ────────────────────────────────────────────────────────
class TestScope(unittest.TestCase):
    def test_out_of_scope_seed_yields_nothing(self):
        server = InMemoryInteractionServer()
        engine = WebAttackEngine(ScopeGuard({"authorised.test"}),
                                 client=VulnApp(server), interaction_server=server,
                                 timing=TimingOracle(trials=1))
        report = engine.run("https://someone-elses-site.test/")
        self.assertEqual(report.pages_crawled, 0)
        self.assertEqual(len(report.findings), 0)


if __name__ == "__main__":
    unittest.main()
