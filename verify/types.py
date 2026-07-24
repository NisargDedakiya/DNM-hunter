"""Core types for the verification layer.

The verification layer answers one question deterministically: *is this candidate
finding actually exploitable against the live target?* An LLM may **propose** the
candidate (injection point, payload shape, the two identities to compare), but it
never decides the verdict — a deterministic oracle does, from observable evidence
(a measured time delay, a raw reflected marker, an out-of-band callback, a
response diff). That boundary is the whole point: it stops the classic failure
mode where an AI "confirms" a finding it actually hallucinated.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Verdict(str, Enum):
    """Outcome of a verification attempt."""
    CONFIRMED = "confirmed"        # an oracle deterministically proved exploitability
    REFUTED = "refuted"            # an oracle proved it is NOT exploitable (false positive)
    INCONCLUSIVE = "inconclusive"  # no oracle could decide — needs a different signal / manual review
    SKIPPED = "skipped"            # not attempted (out of authorised scope, or no oracle for the class)


class VulnClass(str, Enum):
    """Finding classes the verification layer knows how to test."""
    BLIND_SQLI = "blind_sqli"        # time-based blind SQL injection
    BOOLEAN_SQLI = "boolean_sqli"    # boolean-based blind SQL injection
    BLIND_CMDI = "blind_cmdi"        # time-based blind OS command injection
    REFLECTED_XSS = "reflected_xss"  # reflected cross-site scripting
    SSRF = "ssrf"                    # server-side request forgery (out-of-band)
    BLIND_RCE = "blind_rce"          # blind remote code execution (out-of-band)
    IDOR = "idor"                    # insecure direct object reference / BOLA
    BOLA = "bola"                    # (alias) broken object-level authorization
    BFLA = "bfla"                    # broken function-level authorization
    EMAIL_HEADER_INJECTION = "email_header_injection"  # CRLF into mail headers (Bcc/Cc/Subject)
    FORM_ABUSE = "form_abuse"        # state-changing form with no rate-limiting (spam / mail flood)


@dataclass
class Evidence:
    """A single deterministic observation supporting a verdict."""
    kind: str            # "timing" | "reflection" | "oob-interaction" | "response-diff"
    detail: str          # human-readable one-liner
    data: dict = field(default_factory=dict)  # structured backing data

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Identity:
    """A caller identity for authorization testing (a set of auth headers/cookies)."""
    name: str                                  # "owner", "other-user", "anonymous"
    headers: dict = field(default_factory=dict)
    authorized: bool = False                   # is this identity *expected* to have access?


@dataclass
class Candidate:
    """A finding to verify. The AI/scanner fills this in; the engine tests it."""
    vuln_class: str
    target: str                                # full URL
    method: str = "GET"
    param: str = ""                            # injection point: query key / body field / header name
    param_in: str = "query"                    # "query" | "body" | "header"
    base_value: str = ""                       # the benign value the param normally carries
    form_fields: dict = field(default_factory=dict)  # sibling form fields (benign) to co-submit
    headers: dict = field(default_factory=dict)
    identities: list[Identity] = field(default_factory=list)  # for differential (IDOR/BOLA/BFLA)
    owner_marker: str = ""                     # a string only the owner's response should contain
    source_rule: str = ""                      # originating detector (e.g. "CA-SQLI", "WP-...")
    note: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


@dataclass
class VerificationResult:
    verdict: str                               # Verdict value
    vuln_class: str
    oracle: str                                # which oracle produced the verdict
    confidence: float                          # 0.0–1.0 (1.0 = out-of-band / deterministic proof)
    evidence: list[Evidence] = field(default_factory=list)
    note: str = ""
    source_rule: str = ""

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "vuln_class": self.vuln_class,
            "oracle": self.oracle,
            "confidence": round(self.confidence, 3),
            "evidence": [e.to_dict() for e in self.evidence],
            "note": self.note,
            "source_rule": self.source_rule,
        }
