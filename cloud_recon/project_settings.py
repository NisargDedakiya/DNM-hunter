"""Cloud Recon Project Settings - Fetch bucket-enumeration configuration from webapp API."""
import os
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_CLOUD_RECON_SETTINGS: dict[str, Any] = {
    'CLOUD_RECON_ENABLED': False,
    'CLOUD_RECON_SEEDS': '',
    'CLOUD_RECON_PROVIDERS': 'aws_s3,gcs,azure_blob',
}


def fetch_cloud_recon_settings(project_id: str, webapp_url: str) -> dict[str, Any]:
    import requests

    url = f"{webapp_url.rstrip('/')}/api/projects/{project_id}"
    logger.info(f"Fetching cloud recon settings from {url}")

    _internal_headers = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}
    response = requests.get(url, timeout=30, headers=_internal_headers)
    response.raise_for_status()
    project = response.json()

    settings = DEFAULT_CLOUD_RECON_SETTINGS.copy()
    settings['CLOUD_RECON_ENABLED'] = project.get('cloudReconEnabled', DEFAULT_CLOUD_RECON_SETTINGS['CLOUD_RECON_ENABLED'])
    settings['CLOUD_RECON_SEEDS'] = project.get('cloudReconSeeds', DEFAULT_CLOUD_RECON_SETTINGS['CLOUD_RECON_SEEDS'])
    settings['CLOUD_RECON_PROVIDERS'] = project.get('cloudReconProviders', DEFAULT_CLOUD_RECON_SETTINGS['CLOUD_RECON_PROVIDERS'])

    logger.info(f"Loaded {len(settings)} cloud recon settings for project {project_id}")
    return settings


_settings: Optional[dict[str, Any]] = None
_current_project_id: Optional[str] = None


def get_settings() -> dict[str, Any]:
    global _settings
    if _settings is not None:
        return _settings
    return DEFAULT_CLOUD_RECON_SETTINGS.copy()


def load_project_settings(project_id: str) -> dict[str, Any]:
    global _settings, _current_project_id

    if _current_project_id == project_id and _settings is not None:
        return _settings

    webapp_url = os.environ.get('WEBAPP_API_URL')
    if not webapp_url:
        logger.warning("WEBAPP_API_URL not set, using DEFAULT_CLOUD_RECON_SETTINGS")
        _settings = DEFAULT_CLOUD_RECON_SETTINGS.copy()
        _current_project_id = project_id
        return _settings

    try:
        _settings = fetch_cloud_recon_settings(project_id, webapp_url)
        _current_project_id = project_id
        return _settings
    except Exception as e:
        logger.error(f"Failed to fetch cloud recon settings for project {project_id}: {e}")
        _settings = DEFAULT_CLOUD_RECON_SETTINGS.copy()
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
