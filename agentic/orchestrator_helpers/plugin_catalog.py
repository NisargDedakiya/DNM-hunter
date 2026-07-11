"""
Plugin catalog loader (Phase 11).

Reads every manifest.json-style file under the repo-root plugins/ directory
and serves them as one catalog. This is metadata ABOUT capabilities that
already exist (MCP servers, built-in skills, webapp subsystems) — it does
not register or run anything itself. See plugins/README.md.
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# agentic/orchestrator_helpers/plugin_catalog.py -> agentic/ -> repo root -> plugins/
_PLUGINS_DIR = Path(__file__).parent.parent.parent / "plugins"

_VALID_CATEGORIES = {"recon", "scanner", "validator", "reporter", "export"}


def list_plugins() -> list[dict]:
    """Discover all plugin manifests and return their catalog entries."""
    plugins: list[dict] = []

    if not _PLUGINS_DIR.exists():
        logger.warning(f"Plugins directory not found: {_PLUGINS_DIR}")
        return plugins

    for category_dir in sorted(_PLUGINS_DIR.iterdir()):
        if not category_dir.is_dir() or category_dir.name not in _VALID_CATEGORIES:
            continue
        for manifest_file in sorted(category_dir.glob("*.json")):
            try:
                data = json.loads(manifest_file.read_text(encoding="utf-8"))
            except Exception as exc:
                logger.warning(f"Failed to parse plugin manifest {manifest_file}: {type(exc).__name__}: {exc}")
                continue

            if data.get("category") != category_dir.name:
                logger.warning(
                    f"Plugin manifest {manifest_file} declares category "
                    f"'{data.get('category')}' but lives under '{category_dir.name}/' — using directory."
                )
            data["category"] = category_dir.name
            plugins.append(data)

    return plugins
