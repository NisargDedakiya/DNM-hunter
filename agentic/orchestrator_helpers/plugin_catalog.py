"""
Plugin catalog loader (Phase 11).

Reads every manifest.json-style file under the repo-root plugins/ directory
and serves them as one catalog. This is metadata ABOUT capabilities that
already exist (MCP servers, built-in skills, webapp subsystems) — it does
not register or run anything itself. See plugins/README.md.
"""

import asyncio
import json
import logging
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# agentic/orchestrator_helpers/plugin_catalog.py -> agentic/ -> repo root -> plugins/
_PLUGINS_DIR = Path(__file__).parent.parent.parent / "plugins"

_VALID_CATEGORIES = {"recon", "scanner", "validator", "reporter", "export"}

_HEALTH_CHECK_TIMEOUT_SECONDS = 1.5


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


async def _check_one_health(plugin: dict) -> dict:
    """Probe a single plugin's runtime reachability.

    mcp-server plugins are reachable at dockerService:mcpPort on the
    Docker Compose network; a TCP connect is enough to distinguish
    "the container/port is up" from "it's down or misconfigured".
    builtin/webapp-subsystem plugins run in-process with whatever
    already-running service serves this request, so they're reported
    active without a network round-trip.
    """
    plugin_id = plugin.get("id", "unknown")
    kind = plugin.get("kind")
    started = time.monotonic()

    if kind != "mcp-server":
        return {"id": plugin_id, "health": "active", "latencyMs": None, "detail": None}

    host = plugin.get("dockerService")
    port = plugin.get("mcpPort")
    if not host or not port:
        return {"id": plugin_id, "health": "unknown", "latencyMs": None, "detail": "manifest missing dockerService/mcpPort"}

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=_HEALTH_CHECK_TIMEOUT_SECONDS
        )
        writer.close()
        await writer.wait_closed()
        latency_ms = round((time.monotonic() - started) * 1000, 1)
        return {"id": plugin_id, "health": "healthy", "latencyMs": latency_ms, "detail": None}
    except Exception as exc:
        return {"id": plugin_id, "health": "unreachable", "latencyMs": None, "detail": f"{type(exc).__name__}: {exc}"}


async def check_plugins_health(plugins: list[dict] | None = None) -> list[dict]:
    """Concurrently probe every plugin's reachability. Never raises — a
    failed probe is reported as an "unreachable"/"unknown" entry, not an
    exception, so one bad plugin can't take the whole health check down."""
    if plugins is None:
        plugins = list_plugins()
    results = await asyncio.gather(*(_check_one_health(p) for p in plugins))
    return list(results)
