"""Active web-injection engine — crawl a target, generate injection candidates,
and confirm each one through the deterministic verification oracles.

Pipeline:

    seed URL ─▶ Crawler ─▶ AttackSurface (params/forms)
                              │
                              ├─▶ candidate per (injection point × vuln class)
                              │
                              └─▶ VerificationEngine  (scope gate + oracles)
                                        │
                                        └─▶ CONFIRMED findings, with evidence

The engine only *reports* what an oracle CONFIRMED — a reflected marker returned
raw, a response that slowed under an injected delay, an out-of-band callback. It
never reports a payload it merely sent. Everything is scope-gated: the crawler
won't leave the authorised host and the verifier refuses out-of-scope targets.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from verify import (
    Candidate,
    HttpClient,
    InteractionServer,
    ScopeGuard,
    Verdict,
    VerificationEngine,
    VerificationResult,
    VulnClass,
)
from verify.oracles import TimingOracle

from .crawl import Crawler, InjectionPoint

# Classes worth actively testing. The first four are per-parameter injections;
# FORM_ABUSE and EMAIL_HEADER_INJECTION are form-scoped (see run()). BLIND_SQLI
# routes through timing→boolean inside the verifier, so BOOLEAN_SQLI isn't listed.
DEFAULT_CLASSES = [VulnClass.BLIND_SQLI, VulnClass.REFLECTED_XSS,
                   VulnClass.BLIND_CMDI, VulnClass.SSRF,
                   VulnClass.FORM_ABUSE, VulnClass.EMAIL_HEADER_INJECTION]

# The two form-scoped classes are generated per form/endpoint, not per param.
_FORM_SCOPED = (VulnClass.FORM_ABUSE, VulnClass.EMAIL_HEADER_INJECTION)

# Per-class reporting metadata for a CONFIRMED finding.
_CLASS_META = {
    VulnClass.BLIND_SQLI:   ("server_side_injection.sql_injection", "critical", "CWE-89",
                             "SQL injection"),
    VulnClass.BOOLEAN_SQLI: ("server_side_injection.sql_injection", "critical", "CWE-89",
                             "SQL injection"),
    VulnClass.REFLECTED_XSS: ("cross_site_scripting.reflected", "high", "CWE-79",
                              "Reflected cross-site scripting"),
    VulnClass.BLIND_CMDI:   ("server_side_injection.rce", "critical", "CWE-78",
                             "OS command injection"),
    VulnClass.BLIND_RCE:    ("server_side_injection.rce", "critical", "CWE-78",
                             "Remote code execution"),
    VulnClass.SSRF:         ("server_security_misconfiguration.server_side_request_forgery",
                             "high", "CWE-918", "Server-side request forgery"),
    VulnClass.EMAIL_HEADER_INJECTION: (
        "server_side_injection.email_header_injection", "medium", "CWE-93",
        "Email/SMTP header injection"),
    VulnClass.FORM_ABUSE: (
        "server_security_misconfiguration.no_rate_limiting_on_form", "low", "CWE-799",
        "No rate limiting on form (abuse / mail flooding)"),
}

# Short, stable rule id per class (surfaces as WA-* in the report/UI).
_RULE_ID = {
    VulnClass.BLIND_SQLI: "WA-SQLI", VulnClass.BOOLEAN_SQLI: "WA-SQLI",
    VulnClass.REFLECTED_XSS: "WA-XSS", VulnClass.BLIND_CMDI: "WA-CMDI",
    VulnClass.BLIND_RCE: "WA-RCE", VulnClass.SSRF: "WA-SSRF",
    VulnClass.EMAIL_HEADER_INJECTION: "WA-EMAILHDR", VulnClass.FORM_ABUSE: "WA-FORMABUSE",
}

# Param-name hints that indicate a URL-taking parameter (worth SSRF testing).
_URL_HINTS = ("url", "uri", "link", "callback", "redirect", "dest", "continue",
              "return", "next", "path", "file", "page", "feed", "host", "domain",
              "site", "img", "image", "src", "load", "fetch", "proxy", "open", "u")


# Field-name hints that a form field flows into an email header (naive contact
# forms drop these straight into the To/From/Subject/Reply-To header block).
_EMAIL_FIELD_HINTS = ("email", "e-mail", "mail", "name", "subject", "from",
                      "reply", "sender", "cc", "bcc", "phone")


def _is_url_param(name: str) -> bool:
    n = name.lower()
    return any(h in n for h in _URL_HINTS)


def _is_email_field(name: str) -> bool:
    n = name.lower()
    return any(h in n for h in _EMAIL_FIELD_HINTS)


def _benign_value(name: str) -> str:
    """A plausible valid value for a field, so a co-submitted form validates."""
    n = name.lower()
    if "email" in n or "mail" in n:
        return "probe@example.com"
    if "phone" in n or "tel" in n:
        return "5551230000"
    if "name" in n:
        return "Probe Tester"
    if "subject" in n:
        return "Hello"
    if "message" in n or "comment" in n or "body" in n or "content" in n or "detail" in n:
        return "This is a test message."
    if "url" in n or "site" in n or "web" in n:
        return "https://example.com"
    return "test"


def candidates_for(point: InjectionPoint, classes: list[str]) -> list[Candidate]:
    """One Candidate per (injection point × applicable per-parameter vuln class).

    Form-scoped classes (FORM_ABUSE, EMAIL_HEADER_INJECTION) are skipped here —
    the engine generates those once per form in run()."""
    out: list[Candidate] = []
    for vc in classes:
        if vc in _FORM_SCOPED:
            continue
        # SSRF is only meaningful on a parameter that takes a URL/host.
        if vc == VulnClass.SSRF and not _is_url_param(point.param):
            continue
        out.append(Candidate(
            vuln_class=vc, target=point.url, method=point.method,
            param=point.param, param_in=point.param_in,
            base_value=point.base_value or "1",
            source_rule=f"WA-{vc.value.upper()}" if hasattr(vc, "value") else f"WA-{vc}",
        ))
    return out


def _group_post_forms(surface) -> dict[str, dict]:
    """Reconstruct POST form field-sets from the flat surface: {action_url: {field: base}}."""
    forms: dict[str, dict] = {}
    for pt in surface.points:
        if pt.param_in == "body" and pt.method == "POST":
            forms.setdefault(pt.url, {})[pt.param] = pt.base_value or ""
    return forms


def form_candidates(forms: dict[str, dict], classes: list[str]) -> list[Candidate]:
    """Form-scoped candidates: one FORM_ABUSE per POST form, and one
    EMAIL_HEADER_INJECTION per email-ish field on a POST form. Every candidate
    carries plausible benign values for its sibling fields so the form validates."""
    out: list[Candidate] = []
    for url, fields in forms.items():
        benign = {name: (val or _benign_value(name)) for name, val in fields.items()}
        if VulnClass.FORM_ABUSE in classes:
            out.append(Candidate(
                vuln_class=VulnClass.FORM_ABUSE, target=url, method="POST",
                param="", param_in="body", base_value="", form_fields=benign,
                source_rule="WA-FORMABUSE"))
        if VulnClass.EMAIL_HEADER_INJECTION in classes:
            for name in fields:
                if _is_email_field(name):
                    out.append(Candidate(
                        vuln_class=VulnClass.EMAIL_HEADER_INJECTION, target=url, method="POST",
                        param=name, param_in="body",
                        base_value=benign.get(name, "probe@example.com"),
                        form_fields=benign, source_rule="WA-EMAILHDR"))
    return out


@dataclass
class WebAttackFinding:
    vrt: str
    severity: str
    cwe: str
    title: str
    url: str
    param: str
    method: str
    oracle: str
    confidence: float
    evidence: str
    verdict: str = "confirmed"
    rule_id: str = ""

    def to_dict(self) -> dict:
        # Runner-compatible shape (scanner/rule_id/file/line/detail/vrt/cwe) plus
        # the active-testing extras (verdict/confidence/oracle) so the report can
        # show a "verified" badge. detail leads with the proof.
        return {
            "scanner": "web_attack",
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "file": self.url,
            "line": None,
            "detail": f"Verified via {self.oracle} (confidence {self.confidence:.2f}) "
                      f"at param '{self.param}' ({self.method}): {self.evidence}",
            "vrt": self.vrt,
            "cwe": self.cwe,
            "param": self.param,
            "method": self.method,
            "oracle": self.oracle,
            "confidence": self.confidence,
            "verdict": self.verdict,
        }


@dataclass
class WebAttackReport:
    seed: str
    pages_crawled: int
    injection_points: int
    candidates_tested: int
    findings: list[WebAttackFinding] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "seed": self.seed,
            "pages_crawled": self.pages_crawled,
            "injection_points": self.injection_points,
            "candidates_tested": self.candidates_tested,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }


def _finding_from(result: VerificationResult, cand: Candidate) -> WebAttackFinding:
    vrt, sev, cwe, title = _CLASS_META.get(
        result.vuln_class, ("server_side_injection", "medium", "", result.vuln_class))
    detail = result.evidence[0].detail if result.evidence else result.note
    rule_id = _RULE_ID.get(result.vuln_class, "WA-INJECT")
    return WebAttackFinding(vrt, sev, cwe, title, cand.target, cand.param, cand.method,
                            result.oracle, result.confidence, detail, rule_id=rule_id)


class WebAttackEngine:
    def __init__(self, scope: ScopeGuard, client: HttpClient | None = None,
                 interaction_server: InteractionServer | None = None,
                 classes: list[str] | None = None,
                 max_pages: int = 25, max_depth: int = 2,
                 timing: TimingOracle | None = None):
        self.scope = scope
        self.classes = classes or DEFAULT_CLASSES
        self.crawler = Crawler(client, scope, max_pages=max_pages, max_depth=max_depth) if client \
            else None
        self._client = client
        self._interaction_server = interaction_server
        self._timing = timing
        self.verifier = VerificationEngine(scope, client, interaction_server, timing=timing)

    def run(self, seed_url: str) -> WebAttackReport:
        if self.crawler is None:  # pragma: no cover - constructed with a live client in prod
            from verify.http import UrllibHttpClient
            self._client = UrllibHttpClient()
            self.crawler = Crawler(self._client, self.scope)
            self.verifier = VerificationEngine(self.scope, self._client,
                                               self._interaction_server, timing=self._timing)

        surface = self.crawler.crawl(seed_url)
        forms = _group_post_forms(surface)

        # Per-parameter injection candidates. Body params carry their sibling form
        # fields (benign) so a real form validates while one point is injected.
        candidates: list[Candidate] = []
        for point in surface.points:
            fields = forms.get(point.url, {}) if point.param_in == "body" else {}
            benign = {n: (v or _benign_value(n)) for n, v in fields.items()}
            for cand in candidates_for(point, self.classes):
                if cand.param_in == "body":
                    cand.form_fields = benign
                candidates.append(cand)
        # Form-scoped candidates (rate-limit abuse, email header injection).
        candidates.extend(form_candidates(forms, self.classes))

        findings: list[WebAttackFinding] = []
        counts = {v.value: 0 for v in Verdict}
        tested = 0
        for cand in candidates:
            result = self.verifier.verify(cand)
            tested += 1
            counts[result.verdict] = counts.get(result.verdict, 0) + 1
            if result.verdict == Verdict.CONFIRMED:
                findings.append(_finding_from(result, cand))
        # De-duplicate identical confirmed findings (same class+url+param).
        seen: set[tuple] = set()
        unique: list[WebAttackFinding] = []
        for f in findings:
            k = (f.vrt, f.url, f.param, f.method)
            if k not in seen:
                seen.add(k)
                unique.append(f)
        report = WebAttackReport(
            seed=seed_url, pages_crawled=len(surface.pages),
            injection_points=len(surface.points), candidates_tested=tested,
            findings=unique,
            summary={"verdicts": counts, "confirmed": len(unique)},
        )
        return report
