# Plugins

Formal catalog (Phase 11) of the capabilities the agent already has, organized
into the taxonomy the product spec uses: `recon`, `scanner`, `validator`,
`reporter`, `export`.

This directory does **not** introduce a new plugin runtime — every capability
listed here already exists as an MCP server (`mcp/`), a built-in agent skill,
or a webapp subsystem, wired in through the mechanisms those parts of the
codebase already use (`agentic/mcp_registry.py`, `agentic/orchestrator.py`'s
`_build_system_mcp_servers()`, `agentic/skills/`). A manifest here is
metadata *about* an existing capability — id, category, description, which
Docker service backs it, and whether it's a "core" (always available) or
"community" (opt-in, e.g. `agentic/community-skills/`) capability.

`agentic/orchestrator_helpers/plugin_catalog.py` loads every `manifest.json`
under here and serves it through `GET /plugins` (proxied at
`/api/plugins` in the webapp) — the source for the Marketplace browser
(`webapp/src/app/marketplace/page.tsx`).

## Adding a manifest

Drop a `manifest.json` in the right category directory:

```json
{
  "id": "unique-slug",
  "name": "Display Name",
  "category": "recon | scanner | validator | reporter | export",
  "kind": "mcp-server | builtin | webapp-subsystem",
  "description": "One sentence, user-facing.",
  "dockerService": "compose service name backing this, or null",
  "status": "core | community",
  "tags": ["free-text", "tags"]
}
```

`status: "core"` means it ships enabled in every install (part of
`kali-sandbox` or the webapp itself). `status: "community"` means it's an
opt-in import (community skill packs today; a real installer is future
work — see the Marketplace page's own framing).
