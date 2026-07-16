"""Tech-stack-aware contextual impact assessment.

Given a vulnerability class, the target's detected technology stack, and its
exposure context, this adjusts the *real-world* impact — the same bug is not
equally dangerous everywhere. An SSRF against a cloud-hosted app can reach the
metadata service and steal credentials; an internal-only, authenticated variant
is far less severe.

Every adjustment is a rule with an explicit rationale (no ML, fully
explainable), so the output is auditable and defensible in a report. The rules
express widely-accepted security reasoning, not novel claims.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .cvss import severity_rating

# --- Technology taxonomy (lowercased substring signals) ---
_DATABASES = {"mysql", "postgres", "postgresql", "mssql", "sql server", "oracle",
              "mongodb", "mongo", "redis", "elasticsearch", "mariadb"}
_CLOUD = {"aws", "amazon", "gcp", "google cloud", "azure", "s3", "ec2", "lambda"}
_CMS = {"wordpress", "drupal", "joomla", "magento"}
_LANG_DESERIALIZE = {"java", "php", "node", "node.js", "python", "ruby", ".net", "dotnet"}
_FRONTEND_SESSION = {"react", "angular", "vue", "express", "django", "rails", "laravel", "spring"}


@dataclass
class ImpactFactor:
    name: str
    direction: str          # "up" | "down"
    weight: float           # magnitude added/subtracted from the base score
    rationale: str


@dataclass
class ExposureContext:
    internet_facing: bool = True
    authentication_required: bool = False
    handles_sensitive_data: bool = False   # PII, credentials, payment, health
    cloud_hosted: bool = False


@dataclass
class ContextualImpact:
    base_score: float
    contextual_score: float
    base_severity: str
    contextual_severity: str
    factors: list[ImpactFactor] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "baseScore": self.base_score,
            "contextualScore": self.contextual_score,
            "baseSeverity": self.base_severity,
            "contextualSeverity": self.contextual_severity,
            "factors": [
                {"name": f.name, "direction": f.direction, "weight": f.weight, "rationale": f.rationale}
                for f in self.factors
            ],
        }


def _has(stack: list[str], vocab: set[str]) -> bool:
    hay = " ".join(s.lower() for s in stack)
    return any(term in hay for term in vocab)


def assess_contextual_impact(
    vuln_category: str,
    base_score: float,
    tech_stack: list[str] | None = None,
    exposure: ExposureContext | None = None,
) -> ContextualImpact:
    """Adjust a CVSS base score for the target's stack + exposure. The result is
    clamped to [0, 10] and mapped back to a CVSS severity band."""
    cat = (vuln_category or "").lower().strip()
    stack = tech_stack or []
    exp = exposure or ExposureContext()
    factors: list[ImpactFactor] = []

    def add(name, direction, weight, why):
        factors.append(ImpactFactor(name, direction, weight, why))

    # ── Exposure factors (apply to every class) ──
    if exp.internet_facing:
        add("internet-facing", "up", 0.5, "Reachable from the public internet — a remote attacker can trigger it.")
    else:
        add("internal-only", "down", 1.0, "Not internet-facing — exploitation requires prior internal access.")
    if exp.authentication_required:
        add("auth-required", "down", 0.8, "Authentication is required, shrinking the pool of potential attackers.")
    else:
        add("unauthenticated", "up", 0.6, "No authentication required to reach the vulnerable surface.")
    if exp.handles_sensitive_data:
        add("sensitive-data", "up", 0.7, "The application handles sensitive data (PII/credentials/payment), raising confidentiality impact.")

    # ── Class × stack escalations (widely-accepted reasoning) ──
    if cat == "ssrf" and (exp.cloud_hosted or _has(stack, _CLOUD)):
        add("ssrf-cloud-metadata", "up", 2.0,
            "SSRF on cloud infrastructure can reach the instance metadata service (169.254.169.254) and steal IAM credentials — often a full account compromise.")
    if cat in ("sqli", "sql injection", "sqli_exploitation") and _has(stack, _DATABASES):
        add("sqli-database-backed", "up", 1.5,
            "A reachable database backend makes this SQLi a direct path to mass data exfiltration and possible authentication bypass.")
    if cat in ("rce", "command injection", "deserialization") and not exp.internet_facing:
        add("rce-internal-lateral", "up", 1.0,
            "Even internal, RCE is a pivot point for lateral movement across the network.")
    if cat in ("deserialization", "rce") and _has(stack, _LANG_DESERIALIZE):
        add("deserialization-runtime", "up", 1.0,
            "The runtime is known to support gadget-chain deserialization, making reliable code execution more likely.")
    if cat in ("xss", "xss_exploitation") and _has(stack, _FRONTEND_SESSION):
        add("xss-session-theft", "up", 0.8,
            "A session-cookie-based framework means XSS can lead to account takeover, not just defacement.")
    if cat in ("idor", "bola", "idor_bola_exploitation") and exp.handles_sensitive_data:
        add("idor-sensitive-records", "up", 1.0,
            "Direct object references over sensitive records make this a bulk data-exposure risk.")
    if _has(stack, _CMS):
        add("known-cms", "up", 0.5,
            "A widely-deployed CMS expands the exploit surface (known plugin CVEs, public PoCs).")

    # ── Combine ──
    delta = sum(f.weight if f.direction == "up" else -f.weight for f in factors)
    contextual = max(0.0, min(10.0, round(base_score + delta, 1)))

    return ContextualImpact(
        base_score=base_score,
        contextual_score=contextual,
        base_severity=severity_rating(base_score),
        contextual_severity=severity_rating(contextual),
        factors=factors,
    )
