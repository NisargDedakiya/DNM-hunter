"""
Named AI agent role roster.

The engagement is ultimately still one LangGraph ReAct loop (AgentOrchestrator)
plus ephemeral Fireteam members dispatched by it — see fireteam_member_graph.py
and nodes/fireteam_deploy_node.py. Rewriting that into N separately-running
agent processes is out of scope for a single pass (it is the load-bearing
subsystem for every phase already shipped).

What this module adds is the missing piece: a canonical, named roster the
product can talk about consistently — in the fireteam deploy plan, in the UI,
in documentation — instead of the LLM inventing an ad-hoc specialization name
per dispatch. `role` on FireteamMemberSpec (state.py) is optional; when a
dispatched member declares one of the DISPATCHABLE_ROLE_IDS below, its persona
blurb is prefixed onto the member's system prompt (see
nodes/fireteam_member_think_node.py::_build_member_prompt). Everything degrades
gracefully when role is absent — this is purely additive.

PLANNER, COORDINATOR and MEMORY are root-level roles fulfilled by the parent
AgentOrchestrator itself (upfront recon planning, fireteam dispatch/merge, and
the Neo4j knowledge graph respectively) — they are never assigned to a
dispatched fireteam member, but are listed here so the roster is complete and
the UI/API can describe the whole engagement, not just the dispatchable slice.
"""

from typing import Optional, TypedDict


class AgentRole(TypedDict):
    id: str
    label: str
    summary: str
    persona: str
    icon: str
    dispatchable: bool
    typical_tools: list[str]


AGENT_ROLES: list[AgentRole] = [
    {
        "id": "planner",
        "label": "Planner",
        "summary": "Builds the upfront recon plan and sequences engagement phases.",
        "persona": (
            "You are the Planner. Before any tool runs, you decide what recon "
            "and validation order gives the fastest signal for this target."
        ),
        "icon": "Compass",
        "dispatchable": False,
        "typical_tools": ["query_graph", "web_search"],
    },
    {
        "id": "coordinator",
        "label": "Coordinator",
        "summary": "The root agent loop — deploys fireteam waves and merges their results.",
        "persona": (
            "You are the Coordinator. You decide when a task should fan out to a "
            "fireteam wave, how to split it across members, and how to merge "
            "their findings back into one engagement narrative."
        ),
        "icon": "Waypoints",
        "dispatchable": False,
        "typical_tools": ["query_graph"],
    },
    {
        "id": "recon",
        "label": "Recon Agent",
        "summary": "Passive/active discovery — subdomains, ports, tech fingerprinting.",
        "persona": (
            "You are the Recon Agent. Map the attack surface before anything else "
            "touches it: hosts, ports, technologies, and how they connect."
        ),
        "icon": "Radar",
        "dispatchable": True,
        "typical_tools": [
            "execute_subfinder", "execute_amass", "execute_naabu",
            "execute_nmap", "execute_httpx", "execute_katana", "execute_gau",
            "query_graph",
        ],
    },
    {
        "id": "js",
        "label": "JS Analyst",
        "summary": "Client-side bundle analysis — endpoint/secret extraction, DOM sinks.",
        "persona": (
            "You are the JS Analyst. Pull apart client-side bundles for hidden "
            "endpoints, leaked secrets, and DOM sinks an attacker could reach."
        ),
        "icon": "Code2",
        "dispatchable": True,
        "typical_tools": ["execute_jsluice", "execute_katana", "execute_gau", "kali_shell", "query_graph"],
    },
    {
        "id": "api",
        "label": "API Analyst",
        "summary": "REST/GraphQL/OpenAPI surface mapping and parameter discovery.",
        "persona": (
            "You are the API Analyst. Enumerate the real API surface — documented "
            "and undocumented — and its parameters, auth requirements, and schemas."
        ),
        "icon": "Waypoints",
        "dispatchable": True,
        "typical_tools": ["execute_arjun", "execute_httpx", "execute_ffuf", "kali_shell", "query_graph"],
    },
    {
        "id": "auth",
        "label": "Auth Specialist",
        "summary": "Session, JWT, OAuth, and multi-identity access-control testing.",
        "persona": (
            "You are the Auth Specialist. Test authentication and authorization "
            "boundaries — sessions, tokens, roles — including cross-identity "
            "comparisons via stored credentials."
        ),
        "icon": "KeyRound",
        "dispatchable": True,
        "typical_tools": ["execute_curl", "execute_hydra", "kali_shell", "execute_code", "query_graph"],
    },
    {
        "id": "payload",
        "label": "Payload Engineer",
        "summary": "Crafts and delivers exploitation payloads for confirmed injection points.",
        "persona": (
            "You are the Payload Engineer. Turn a suspected injection point into "
            "a working, minimally-invasive proof of concept."
        ),
        "icon": "Zap",
        "dispatchable": True,
        "typical_tools": ["execute_code", "kali_shell", "execute_curl", "execute_nuclei", "metasploit_console", "query_graph"],
    },
    {
        "id": "scanner",
        "label": "Scanner",
        "summary": "Broad automated sweeps — templated checks, known-CVE matching.",
        "persona": (
            "You are the Scanner. Run broad, automated checks across the surface "
            "to surface candidates for the specialist roles to confirm."
        ),
        "icon": "ScanSearch",
        "dispatchable": True,
        "typical_tools": ["execute_nuclei", "execute_wpscan", "execute_ffuf", "cve_intel", "query_graph"],
    },
    {
        "id": "validator",
        "label": "Validator",
        "summary": "Re-checks candidate findings and scores confidence / false-positive risk.",
        "persona": (
            "You are the Validator. Treat every candidate finding as unproven "
            "until you reproduce it. Score confidence and false-positive risk "
            "honestly — a wrong 'confirmed' is worse than an honest 'needs review'."
        ),
        "icon": "ShieldCheck",
        "dispatchable": True,
        "typical_tools": ["execute_curl", "execute_playwright", "execute_code", "query_graph"],
    },
    {
        "id": "report",
        "label": "Report Writer",
        "summary": "Turns confirmed findings and evidence into a structured writeup.",
        "persona": (
            "You are the Report Writer. Convert confirmed findings and captured "
            "evidence into a clear, reproducible writeup a triager can act on "
            "without asking follow-up questions."
        ),
        "icon": "FileText",
        "dispatchable": True,
        "typical_tools": ["query_graph", "execute_playwright"],
    },
    {
        "id": "memory",
        "label": "Memory Keeper",
        "summary": "Curates the engagement's knowledge graph so nothing is re-discovered twice.",
        "persona": (
            "You are the Memory Keeper. Every finding, failure, and captured "
            "artifact you see should be attributable and re-findable later."
        ),
        "icon": "Database",
        "dispatchable": False,
        "typical_tools": ["query_graph"],
    },
]

_ROLES_BY_ID: dict[str, AgentRole] = {r["id"]: r for r in AGENT_ROLES}

DISPATCHABLE_ROLE_IDS: list[str] = [r["id"] for r in AGENT_ROLES if r["dispatchable"]]


def get_role(role_id: str) -> Optional[AgentRole]:
    """Look up a role by id. Returns None for unknown/blank ids (non-fatal —
    callers should treat this as 'no role declared', not an error)."""
    if not role_id:
        return None
    return _ROLES_BY_ID.get(role_id)


def list_roles() -> list[AgentRole]:
    return list(AGENT_ROLES)
