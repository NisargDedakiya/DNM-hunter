"""Verification engine — routes a candidate to the right oracle(s), enforces the
authorisation scope, and aggregates verdicts.

Design boundary (the reason this layer exists): the AI/scanner decides *what* to
test (it fills in Candidate: the injection point, the base value, the two
identities). The engine and its oracles decide *whether it's real*, purely from
observable evidence. No model output ever becomes a verdict.
"""

from __future__ import annotations

from .http import HttpClient, UrllibHttpClient
from .oracles import (
    BooleanOracle,
    DifferentialOracle,
    EmailHeaderInjectionOracle,
    InteractionServer,
    OastOracle,
    RateLimitOracle,
    ReflectionOracle,
    TimingOracle,
)
from .scope import ScopeGuard
from .types import Candidate, Verdict, VerificationResult, VulnClass

# Verdict strength for aggregation when several oracles run for one class.
_STRENGTH = {Verdict.CONFIRMED: 3, Verdict.REFUTED: 2, Verdict.INCONCLUSIVE: 1, Verdict.SKIPPED: 0}


class VerificationEngine:
    def __init__(self, scope: ScopeGuard, client: HttpClient | None = None,
                 interaction_server: InteractionServer | None = None,
                 timing: TimingOracle | None = None):
        self.scope = scope
        self.client = client or UrllibHttpClient()
        self.timing = timing or TimingOracle()
        self.boolean = BooleanOracle()
        self.reflection = ReflectionOracle()
        self.differential = DifferentialOracle()
        self.rate_limit = RateLimitOracle()
        self.email_header = EmailHeaderInjectionOracle(interaction_server)
        self.oast = OastOracle(interaction_server) if interaction_server else None

    def _oracles_for(self, vuln_class: str) -> list:
        """Ordered list of oracles to try for a class (first CONFIRMED wins)."""
        vc = vuln_class
        if vc == VulnClass.BLIND_SQLI:
            return [self.timing, self.boolean]
        if vc == VulnClass.BOOLEAN_SQLI:
            return [self.boolean]
        if vc == VulnClass.BLIND_CMDI:
            # Confirm command injection with the `sleep` timing probe. OAST is
            # NOT used here: a `curl http://<oast>` payload injected at a param
            # that is actually an SSRF sink would cross-trigger a callback and be
            # misread as command execution. OAST stays reserved for SSRF/RCE.
            return [self.timing]
        if vc == VulnClass.REFLECTED_XSS:
            return [self.reflection]
        if vc in (VulnClass.SSRF, VulnClass.BLIND_RCE):
            return [self.oast] if self.oast else []
        if vc in (VulnClass.IDOR, VulnClass.BOLA, VulnClass.BFLA):
            return [self.differential]
        if vc == VulnClass.FORM_ABUSE:
            return [self.rate_limit]
        if vc == VulnClass.EMAIL_HEADER_INJECTION:
            return [self.email_header]
        return []

    def verify(self, cand: Candidate) -> VerificationResult:
        # 1) authorisation gate — active testing is refused outside scope.
        if not self.scope.is_allowed(cand.target):
            return VerificationResult(Verdict.SKIPPED, cand.vuln_class, "scope-guard", 0.0, [],
                                      self.scope.reason(cand.target), cand.source_rule)
        # 2) route to oracle(s).
        oracles = self._oracles_for(cand.vuln_class)
        if not oracles:
            return VerificationResult(Verdict.SKIPPED, cand.vuln_class, "engine", 0.0, [],
                                      f"No verification oracle for class '{cand.vuln_class}' "
                                      f"(needs SSRF/blind-RCE OAST server, or a dynamic-only class).",
                                      cand.source_rule)
        # 3) run in order; a CONFIRMED short-circuits, otherwise keep the strongest.
        best: VerificationResult | None = None
        for oracle in oracles:
            result = oracle.verify(cand, self.client)
            if result.verdict == Verdict.CONFIRMED:
                return result
            if best is None or _STRENGTH[Verdict(result.verdict)] > _STRENGTH[Verdict(best.verdict)]:
                best = result
        return best  # type: ignore[return-value]

    def verify_all(self, candidates: list[Candidate]) -> list[VerificationResult]:
        return [self.verify(c) for c in candidates]
