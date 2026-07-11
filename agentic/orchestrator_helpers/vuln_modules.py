"""
Vulnerability module registry.

Unifies the two vulnerability-class systems that already exist in this
codebase into one catalog, each entry tagged with the named agent role
(see agent_roles.py) best suited to run it:

  - "builtin"   — the 9 classes in prompts/classification.py's
                   _BUILTIN_SKILL_MAP. These are fully automated: the main
                   ReAct loop classifies user intent into one of these,
                   injects a dedicated workflow, and scopes the phase
                   toolset accordingly (see prompts/base.py
                   _inject_builtin_skill_workflow).
  - "skills" / "community-skills" — markdown methodology guides under
                   agentic/skills/{vulnerabilities,api_security}/ and
                   agentic/community-skills/. These back the Manual Hunt
                   Wizard (webapp /programs/[id]/wizard) — coaching for
                   classes automation can't yet fully confirm on its own.

Nothing here re-implements scanning logic; it only catalogs what already
exists so the API/UI can present one coherent module list instead of two
disconnected systems.
"""

from pathlib import Path
from typing import Optional, TypedDict

from orchestrator_helpers.skill_loader import list_skills as _list_agent_skills

_COMMUNITY_SKILLS_DIR = Path(__file__).parent.parent / "community-skills"

# Vulnerability classes fully wired into the main ReAct loop's classification
# + workflow-injection system (prompts/classification.py _BUILTIN_SKILL_MAP).
# Blurbs summarize (not duplicate) the classification sections there.
_BUILTIN_MODULES: list[tuple[str, str, str, str]] = [
    # (id, title, blurb, suggested_role)
    ("sql_injection", "SQL Injection", "Error/union/blind/OOB injection via sqlmap and manual technique, including WAF and auth bypass.", "payload"),
    ("xss", "Cross-Site Scripting", "Reflected/stored/DOM/blind XSS via dalfox, kxss, and context-aware manual payloads.", "payload"),
    ("ssrf", "SSRF", "Cloud-metadata pivots, protocol smuggling, DNS rebinding, and internal port scanning via forced server-side requests.", "payload"),
    ("rce", "Remote Code Execution", "Command injection, SSTI, deserialization gadget chains, and media/document pipeline RCE.", "payload"),
    ("path_traversal", "Path Traversal / LFI / RFI", "PHP wrapper abuse, log poisoning, and archive Zip Slip for out-of-root file reads.", "payload"),
    ("cve_exploit", "CVE Exploitation (MSF)", "Direct exploitation of known CVEs against a service using Metasploit modules.", "scanner"),
    ("brute_force_credential_guess", "Credential Brute Force", "Password guessing / dictionary attacks against login services via Hydra.", "auth"),
    ("phishing_social_engineering", "Phishing / Payload Delivery", "Payload generation and delivery for target-user-executed artifacts.", "payload"),
    ("denial_of_service", "Denial of Service", "Availability-disruption testing — flooding, resource exhaustion, crash triggers.", "scanner"),
]

# suggested_role per skill-doc id (agentic/skills/{vulnerabilities,api_security}/*.md).
_SKILL_ROLE_OVERRIDES: dict[str, str] = {
    "vulnerabilities/business_logic": "api",
    "vulnerabilities/clickjacking": "scanner",
    "vulnerabilities/cors_misconfig": "api",
    "vulnerabilities/crlf_injection": "payload",
    "vulnerabilities/csrf": "auth",
    "vulnerabilities/host_header_injection": "payload",
    "vulnerabilities/http_request_smuggling": "payload",
    "vulnerabilities/information_disclosure": "recon",
    "vulnerabilities/jwt_attacks": "auth",
    "vulnerabilities/ldap_injection": "payload",
    "vulnerabilities/oauth_oidc": "auth",
    "vulnerabilities/open_redirect": "payload",
    "vulnerabilities/prototype_pollution": "js",
    "vulnerabilities/race_conditions": "payload",
    "vulnerabilities/redos": "payload",
    "vulnerabilities/two_fa_otp_bypass": "auth",
    "vulnerabilities/web_cache_poisoning": "payload",
    "vulnerabilities/xpath_injection": "payload",
    "api_security/openapi_swagger_exposure": "api",
}

# suggested_role per community-skill id (agentic/community-skills/*.md).
_COMMUNITY_ROLE_OVERRIDES: dict[str, str] = {
    "sqli_exploitation": "payload",
    "xss_exploitation": "payload",
    "ssti": "payload",
    "xxe": "payload",
    "insecure_deserialization": "payload",
    "insecure_file_uploads": "payload",
    "mass_assignment": "api",
    "bfla_exploitation": "auth",
    "idor_bola_exploitation": "auth",
    "subdomain_takeover": "recon",
    "api_testing": "api",
}

_DEFAULT_ROLE = "scanner"


class VulnModule(TypedDict):
    id: str
    title: str
    blurb: str
    source: str  # "builtin" | "skills" | "community-skills"
    skill_id: Optional[str]  # id to pass to GET /skills/{id} or /community-skills/{id}; None for builtin
    automated: bool
    suggested_role: str


def list_vuln_modules() -> list[VulnModule]:
    modules: list[VulnModule] = []

    for module_id, title, blurb, role in _BUILTIN_MODULES:
        modules.append({
            "id": f"builtin:{module_id}",
            "title": title,
            "blurb": blurb,
            "source": "builtin",
            "skill_id": None,
            "automated": True,
            "suggested_role": role,
        })

    for skill in _list_agent_skills():
        if skill["category"] not in ("vulnerabilities", "api_security"):
            continue
        role = _SKILL_ROLE_OVERRIDES.get(skill["id"], _DEFAULT_ROLE)
        modules.append({
            "id": f"skills:{skill['id']}",
            "title": skill["name"],
            "blurb": skill["description"],
            "source": "skills",
            "skill_id": skill["id"],
            "automated": False,
            "suggested_role": role,
        })

    if _COMMUNITY_SKILLS_DIR.exists():
        for md_file in sorted(_COMMUNITY_SKILLS_DIR.glob("*.md")):
            if md_file.name == "README.md":
                continue
            skill_id = md_file.stem
            content = md_file.read_text(encoding="utf-8")
            name = skill_id.replace("_", " ").title()
            desc = ""
            for line in content.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    desc = stripped[:200]
                    break
            role = _COMMUNITY_ROLE_OVERRIDES.get(skill_id, _DEFAULT_ROLE)
            modules.append({
                "id": f"community-skills:{skill_id}",
                "title": name,
                "blurb": desc,
                "source": "community-skills",
                "skill_id": skill_id,
                "automated": False,
                "suggested_role": role,
            })

    return modules
