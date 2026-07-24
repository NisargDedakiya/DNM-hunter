"""
IaC Scan Project Settings - Fetch DevOps/IaC scan configuration from webapp API.

Mirrors the pattern from trufflehog_scan/project_settings.py.
"""
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_IAC_SETTINGS: dict[str, Any] = {
    'GITHUB_ACCESS_TOKEN': os.getenv('GITHUB_ACCESS_TOKEN', ''),
    'IAC_SCAN_ENABLED': False,
    'IAC_SCAN_GITHUB_ORG': '',
    'IAC_SCAN_GITHUB_REPOS': '',
}


def _get_json(url: str, headers: dict[str, str]) -> Any:
    """GET a URL and parse JSON using only the stdlib (keeps the suite dep-free)."""
    import json
    import urllib.request

    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_iac_settings(project_id: str, webapp_url: str) -> dict[str, Any]:
    url = f"{webapp_url.rstrip('/')}/api/projects/{project_id}"
    logger.info(f"Fetching IaC scan settings from {url}")

    _internal_headers = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}
    project = _get_json(url, _internal_headers)

    settings = DEFAULT_IAC_SETTINGS.copy()

    user_id = os.environ.get('USER_ID', '')
    if user_id:
        try:
            user_settings_url = f"{webapp_url.rstrip('/')}/api/users/{user_id}/settings?internal=true"
            user_settings = _get_json(user_settings_url, _internal_headers)
            settings['GITHUB_ACCESS_TOKEN'] = user_settings.get('githubAccessToken', DEFAULT_IAC_SETTINGS['GITHUB_ACCESS_TOKEN'])
        except Exception as e:
            logger.warning(f"Failed to fetch user settings for GitHub token: {e}")

    settings['IAC_SCAN_ENABLED'] = project.get('iacScanEnabled', DEFAULT_IAC_SETTINGS['IAC_SCAN_ENABLED'])
    settings['IAC_SCAN_GITHUB_ORG'] = project.get('iacScanGithubOrg', DEFAULT_IAC_SETTINGS['IAC_SCAN_GITHUB_ORG'])
    settings['IAC_SCAN_GITHUB_REPOS'] = project.get('iacScanGithubRepos', DEFAULT_IAC_SETTINGS['IAC_SCAN_GITHUB_REPOS'])

    logger.info(f"Loaded {len(settings)} IaC scan settings for project {project_id}")
    return settings


_settings: dict[str, Any] | None = None
_current_project_id: str | None = None


def get_settings() -> dict[str, Any]:
    global _settings
    if _settings is not None:
        return _settings
    logger.info("Using DEFAULT_IAC_SETTINGS (no project loaded yet)")
    return DEFAULT_IAC_SETTINGS.copy()


def load_project_settings(project_id: str) -> dict[str, Any]:
    global _settings, _current_project_id

    if _current_project_id == project_id and _settings is not None:
        return _settings

    webapp_url = os.environ.get('WEBAPP_API_URL')

    if not webapp_url:
        logger.warning("WEBAPP_API_URL not set, using DEFAULT_IAC_SETTINGS")
        _settings = DEFAULT_IAC_SETTINGS.copy()
        _current_project_id = project_id
        return _settings

    try:
        _settings = fetch_iac_settings(project_id, webapp_url)
        _current_project_id = project_id
        return _settings
    except Exception as e:
        logger.error(f"Failed to fetch IaC scan settings for project {project_id}: {e}")
        logger.warning("Falling back to DEFAULT_IAC_SETTINGS")
        _settings = DEFAULT_IAC_SETTINGS.copy()
        _current_project_id = project_id
        return _settings


def get_setting(key: str, default: Any = None) -> Any:
    return get_settings().get(key, default)


def reload_settings(project_id: str | None = None) -> dict[str, Any]:
    global _settings, _current_project_id
    if project_id:
        _current_project_id = None
        return load_project_settings(project_id)
    _settings = None
    _current_project_id = None
    return get_settings()
