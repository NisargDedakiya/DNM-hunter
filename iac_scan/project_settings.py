"""
IaC Scan Project Settings - Fetch DevOps/IaC scan configuration from webapp API.

Mirrors the pattern from trufflehog_scan/project_settings.py.
"""
import os
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_IAC_SETTINGS: dict[str, Any] = {
    'GITHUB_ACCESS_TOKEN': os.getenv('GITHUB_ACCESS_TOKEN', ''),
    'IAC_SCAN_ENABLED': False,
    'IAC_SCAN_GITHUB_ORG': '',
    'IAC_SCAN_GITHUB_REPOS': '',
}


def fetch_iac_settings(project_id: str, webapp_url: str) -> dict[str, Any]:
    import requests

    url = f"{webapp_url.rstrip('/')}/api/projects/{project_id}"
    logger.info(f"Fetching IaC scan settings from {url}")

    _internal_headers = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}
    response = requests.get(url, timeout=30, headers=_internal_headers)
    response.raise_for_status()
    project = response.json()

    settings = DEFAULT_IAC_SETTINGS.copy()

    user_id = os.environ.get('USER_ID', '')
    if user_id:
        try:
            user_settings_url = f"{webapp_url.rstrip('/')}/api/users/{user_id}/settings?internal=true"
            user_resp = requests.get(user_settings_url, timeout=30, headers=_internal_headers)
            user_resp.raise_for_status()
            user_settings = user_resp.json()
            settings['GITHUB_ACCESS_TOKEN'] = user_settings.get('githubAccessToken', DEFAULT_IAC_SETTINGS['GITHUB_ACCESS_TOKEN'])
        except Exception as e:
            logger.warning(f"Failed to fetch user settings for GitHub token: {e}")

    settings['IAC_SCAN_ENABLED'] = project.get('iacScanEnabled', DEFAULT_IAC_SETTINGS['IAC_SCAN_ENABLED'])
    settings['IAC_SCAN_GITHUB_ORG'] = project.get('iacScanGithubOrg', DEFAULT_IAC_SETTINGS['IAC_SCAN_GITHUB_ORG'])
    settings['IAC_SCAN_GITHUB_REPOS'] = project.get('iacScanGithubRepos', DEFAULT_IAC_SETTINGS['IAC_SCAN_GITHUB_REPOS'])

    logger.info(f"Loaded {len(settings)} IaC scan settings for project {project_id}")
    return settings


_settings: Optional[dict[str, Any]] = None
_current_project_id: Optional[str] = None


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


def reload_settings(project_id: Optional[str] = None) -> dict[str, Any]:
    global _settings, _current_project_id
    if project_id:
        _current_project_id = None
        return load_project_settings(project_id)
    _settings = None
    _current_project_id = None
    return get_settings()
