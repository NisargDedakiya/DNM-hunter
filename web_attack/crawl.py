"""Attack-surface discovery — crawl a live target and extract the parameters,
forms and endpoints an attacker could inject into.

This is the *discovery* half of active testing: it finds WHERE to test. The
`verify` layer is the *confirmation* half: it decides whether an injection there
actually works. The crawler talks to the target through the same `HttpClient`
abstraction the oracles use, so the whole engine is unit-testable offline, and it
honours the same `ScopeGuard` so it never fetches an unauthorised host.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit

from verify.http import HttpClient, HttpRequest
from verify.scope import ScopeGuard


@dataclass(frozen=True)
class InjectionPoint:
    """A single place user input enters the app: one query key or one form field."""
    url: str            # the URL to send the request to (form action, or the page URL)
    param: str          # parameter / field name
    param_in: str       # "query" | "body"
    method: str         # "GET" | "POST"
    base_value: str = ""  # the benign value observed in the page (kept for baselines)

    def key(self) -> tuple:
        p = urlsplit(self.url)
        return (self.method, p.netloc, p.path, self.param, self.param_in)


@dataclass
class AttackSurface:
    seed: str
    pages: list[str] = field(default_factory=list)
    points: list[InjectionPoint] = field(default_factory=list)


class _SurfaceParser(HTMLParser):
    """Pulls same-page links and forms (with their inputs) out of one HTML page."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base = base_url
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._form: dict | None = None

    # `<input .../>` self-closing tags arrive here — route to the normal handler.
    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_starttag(self, tag, attrs):
        d = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and d.get("href"):
            self.links.append(urljoin(self.base, d["href"]))
        elif tag == "form":
            self._form = {
                "action": urljoin(self.base, d.get("action") or self.base),
                "method": (d.get("method") or "GET").upper(),
                "inputs": [],
            }
        elif tag in ("input", "textarea", "select") and self._form is not None:
            name = d.get("name")
            if name and d.get("type", "").lower() not in ("submit", "button", "image", "reset"):
                self._form["inputs"].append((name, d.get("value", "")))

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _points_from_url(url: str) -> list[InjectionPoint]:
    """Every query parameter on a URL is a GET injection point."""
    q = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    return [InjectionPoint(url, k, "query", "GET", v) for k, v in q]


def _points_from_form(form: dict) -> list[InjectionPoint]:
    method = "POST" if form["method"] == "POST" else "GET"
    where = "body" if method == "POST" else "query"
    return [InjectionPoint(form["action"], name, where, method, val)
            for name, val in form["inputs"]]


class Crawler:
    """Bounded, same-scope BFS crawler that yields an AttackSurface."""

    def __init__(self, client: HttpClient, scope: ScopeGuard,
                 max_pages: int = 25, max_depth: int = 2):
        self.client = client
        self.scope = scope
        self.max_pages = max_pages
        self.max_depth = max_depth

    def crawl(self, seed_url: str) -> AttackSurface:
        surface = AttackSurface(seed=seed_url)
        seen_pages: set[str] = set()
        seen_points: set[tuple] = set()
        queue: deque[tuple[str, int]] = deque([(seed_url, 0)])

        def add_point(pt: InjectionPoint) -> None:
            if pt.key() not in seen_points:
                seen_points.add(pt.key())
                surface.points.append(pt)

        while queue and len(seen_pages) < self.max_pages:
            url, depth = queue.popleft()
            base = url.split("#", 1)[0]
            if base in seen_pages or not self.scope.is_allowed(base):
                continue
            seen_pages.add(base)
            surface.pages.append(base)

            for pt in _points_from_url(base):
                add_point(pt)

            try:
                resp = self.client.send(HttpRequest("GET", base, {}))
            except Exception:
                continue
            if not resp.body:
                continue

            parser = _SurfaceParser(base)
            try:
                parser.feed(resp.body)
            except Exception:
                pass
            for form in parser.forms:
                for pt in _points_from_form(form):
                    if self.scope.is_allowed(pt.url):
                        add_point(pt)
            if depth < self.max_depth:
                for link in parser.links:
                    link = link.split("#", 1)[0]
                    if self.scope.is_allowed(link) and link not in seen_pages:
                        for pt in _points_from_url(link):
                            add_point(pt)
                        queue.append((link, depth + 1))
        return surface
