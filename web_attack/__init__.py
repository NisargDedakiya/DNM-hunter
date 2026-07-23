"""web_attack — active web-injection engine.

Crawls a live target, discovers injectable parameters and forms, and confirms
real vulnerabilities (SQLi, reflected XSS, command injection, SSRF) by driving
them through the deterministic `verify` oracles. Only oracle-CONFIRMED issues are
reported, and every request is scope-gated.

    from web_attack import WebAttackEngine
    from verify import ScopeGuard, InMemoryInteractionServer

    engine = WebAttackEngine(
        scope=ScopeGuard({"staging.example.com"}, allow_subdomains=True),
        interaction_server=InMemoryInteractionServer(),   # real collaborator in prod
    )
    report = engine.run("https://staging.example.com/")
    for f in report.findings:
        print(f.severity, f.title, f.url, f.param, "→", f.evidence)
"""

from .crawl import AttackSurface, Crawler, InjectionPoint
from .engine import (
    DEFAULT_CLASSES,
    WebAttackEngine,
    WebAttackFinding,
    WebAttackReport,
    candidates_for,
)

__all__ = [
    "WebAttackEngine", "WebAttackReport", "WebAttackFinding",
    "Crawler", "AttackSurface", "InjectionPoint",
    "candidates_for", "DEFAULT_CLASSES",
]
