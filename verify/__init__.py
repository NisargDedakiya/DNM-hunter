"""Verification layer — deterministic, oracle-backed confirmation of findings.

The scanner/AI proposes a Candidate; a deterministic oracle decides the verdict
from observable evidence (measured delay, raw reflection, out-of-band callback,
cross-identity response diff). No model output is ever treated as a verdict, and
active testing is refused outside the operator's authorised scope.

    from verify import VerificationEngine, ScopeGuard, Candidate, VulnClass
    from verify import InMemoryInteractionServer

    engine = VerificationEngine(
        scope=ScopeGuard({"staging.example.com"}),
        interaction_server=InMemoryInteractionServer(),
    )
    result = engine.verify(Candidate(
        vuln_class=VulnClass.BLIND_SQLI,
        target="https://staging.example.com/item",
        param="id", base_value="1", source_rule="CA-SQLI",
    ))
    print(result.verdict, result.confidence)
"""

from .engine import VerificationEngine
from .http import HttpClient, HttpRequest, HttpResponse, UrllibHttpClient
from .oracles import (
    BooleanOracle,
    DifferentialOracle,
    EmailHeaderInjectionOracle,
    InMemoryInteractionServer,
    Interaction,
    InteractionServer,
    OastOracle,
    RateLimitOracle,
    ReflectionOracle,
    TimingOracle,
)
from .scope import ScopeGuard
from .types import (
    Candidate,
    Evidence,
    Identity,
    Verdict,
    VerificationResult,
    VulnClass,
)

__all__ = [
    "VerificationEngine", "ScopeGuard",
    "Candidate", "Identity", "Evidence", "VerificationResult", "Verdict", "VulnClass",
    "HttpClient", "HttpRequest", "HttpResponse", "UrllibHttpClient",
    "TimingOracle", "BooleanOracle", "ReflectionOracle", "OastOracle", "DifferentialOracle",
    "RateLimitOracle", "EmailHeaderInjectionOracle",
    "InteractionServer", "InMemoryInteractionServer", "Interaction",
]
