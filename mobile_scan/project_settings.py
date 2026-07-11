"""Mobile Scan Project Settings - Fetch APK static-analysis configuration from webapp API."""
import os
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_MOBILE_SCAN_SETTINGS: dict[str, Any] = {
    'MOBILE_SCAN_ENABLED': False,
}


def fetch_mobile_scan_settings(project_id: str, webapp_url: str) -> dict[str, Any]:
    import requests

    url = f"{webapp_url.rstrip('/')}/api/projects/{project_id}"
    logger.info(f"Fetching mobile scan settings from {url}")

    _internal_headers = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}
    response = requests.get(url, timeout=30, headers=_internal_headers)
    response.raise_for_status()
    project = response.json()

    settings = DEFAULT_MOBILE_SCAN_SETTINGS.copy()
    settings['MOBILE_SCAN_ENABLED'] = project.get('mobileScanEnabled', DEFAULT_MOBILE_SCAN_SETTINGS['MOBILE_SCAN_ENABLED'])
    return settings


_settings: Optional[dict[str, Any]] = None
_current_project_id: Optional[str] = None


def get_settings() -> dict[str, Any]:
    global _settings
    if _settings is not None:
        return _settings
    return DEFAULT_MOBILE_SCAN_SETTINGS.copy()


def load_project_settings(project_id: str) -> dict[str, Any]:
    global _settings, _current_project_id

    if _current_project_id == project_id and _settings is not None:
        return _settings

    webapp_url = os.environ.get('WEBAPP_API_URL')
    if not webapp_url:
        _settings = DEFAULT_MOBILE_SCAN_SETTINGS.copy()
        _current_project_id = project_id
        return _settings

    try:
        _settings = fetch_mobile_scan_settings(project_id, webapp_url)
        _current_project_id = project_id
        return _settings
    except Exception as e:
        logger.error(f"Failed to fetch mobile scan settings for project {project_id}: {e}")
        _settings = DEFAULT_MOBILE_SCAN_SETTINGS.copy()
        _current_project_id = project_id
        return _settings


def get_setting(key: str, default: Any = None) -> Any:
    return get_settings().get(key, default)
