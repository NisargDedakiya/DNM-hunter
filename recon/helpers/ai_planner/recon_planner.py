"""
Upfront Recon AI Planner
========================
Before the discovery pipeline runs, ask the agent for a short plan: what the
target likely is, its guessed tech stack, framework, endpoints worth
prioritizing, which of the already-enabled scanners to run first, a rough
duration estimate, and likely vulnerability classes worth prioritizing.

This is informational by design — see project_settings.py's
RECON_AI_PLANNER_ENABLED comment. The one place callers are expected to act
on it is DNS_MAX_WORKERS, which discover_subdomains() clamps upward for
large-looking targets and downward for tiny ones; it never silently enables
or disables a tool the user configured.

The LLM call is delegated to the agent container's /llm/recon-plan endpoint,
same pattern as waf_classifier.py and takeover_classifier.py.
"""

import json
import os
from typing import Dict, List, Optional

import requests

SAFE_FALLBACK: Dict = {
    "target_summary": "",
    "technology_guess": "unknown",
    "framework_guess": "unknown",
    "interesting_endpoints": [],
    "recommended_scanners": [],
    "estimated_duration_minutes": 0,
    "likely_vulnerabilities": [],
    "source": "ai_unavailable",
}

LLM_TIMEOUT = 25


def _validate_plan(raw) -> Optional[Dict]:
    """Return a sanitized plan dict or None if the payload is malformed."""
    if not isinstance(raw, dict):
        return None

    duration = raw.get("estimated_duration_minutes")
    if not isinstance(duration, (int, float)):
        return None

    def _str_list(key: str) -> List[str]:
        val = raw.get(key)
        if not isinstance(val, list):
            return []
        return [str(x) for x in val if isinstance(x, (str, int, float))]

    return {
        "target_summary": str(raw.get("target_summary") or "")[:500],
        "technology_guess": str(raw.get("technology_guess") or "unknown")[:200],
        "framework_guess": str(raw.get("framework_guess") or "unknown")[:200],
        "interesting_endpoints": _str_list("interesting_endpoints"),
        "recommended_scanners": _str_list("recommended_scanners"),
        "estimated_duration_minutes": max(0, int(duration)),
        "likely_vulnerabilities": _str_list("likely_vulnerabilities"),
        "source": "ai_planner",
    }


def plan_recon(
    domain: str,
    enabled_tools: List[str],
    model: str,
    user_id: str = '',
    project_id: str = '',
) -> Dict:
    """
    Ask the agent for an upfront recon plan for *domain*.
    Never raises — returns ``SAFE_FALLBACK`` on any failure so the pipeline
    always proceeds even if planning is unavailable.
    """
    print(f"[*][Recon-AI-Planner] Planning recon for {domain}...")

    agent_api_url = os.environ.get('AGENT_API_URL', 'http://localhost:8090').rstrip('/')
    payload = {
        'domain': domain,
        'enabled_tools': enabled_tools,
        'model': model,
        'user_id': user_id,
        'project_id': project_id,
    }
    endpoint = f"{agent_api_url}/llm/recon-plan"

    try:
        resp = requests.post(endpoint, json=payload, timeout=LLM_TIMEOUT)
    except requests.RequestException as e:
        print(f"[!][Recon-AI-Planner] Agent request failed: {e}. Skipping plan.")
        return dict(SAFE_FALLBACK)

    if resp.status_code != 200:
        print(f"[!][Recon-AI-Planner] Agent returned HTTP {resp.status_code}: {resp.text[:200]}. Skipping plan.")
        return dict(SAFE_FALLBACK)

    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError) as e:
        print(f"[!][Recon-AI-Planner] Agent returned non-JSON response: {e}. Skipping plan.")
        return dict(SAFE_FALLBACK)

    validated = _validate_plan(data)
    if validated is None:
        print(f"[!][Recon-AI-Planner] Agent response failed schema validation: {str(data)[:200]}. Skipping plan.")
        return dict(SAFE_FALLBACK)

    print(f"[+][Recon-AI-Planner] {validated['target_summary'] or '(no summary)'}")
    print(f"[+][Recon-AI-Planner] Tech guess: {validated['technology_guess']} / {validated['framework_guess']}")
    print(f"[+][Recon-AI-Planner] Est. duration: {validated['estimated_duration_minutes']} min, "
          f"priority scanners: {', '.join(validated['recommended_scanners']) or '(none)'}")

    return validated
