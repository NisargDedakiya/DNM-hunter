# NisargHunter AI — Documentation Index

One entry point for operators and contributors. This index **organizes and
links** the existing documentation under [`readmes/`](../readmes/) rather than
duplicating it — each section points at the authoritative source.

> Master-plan Phase 6, Priority 13. When you add a doc, link it here; don't copy
> content between files.

## Architecture overview

- [System architecture + mermaid diagrams](../readmes/ARCHITECTURE.md)
- [Tech stack](../readmes/TECH_STACK.md)
- [Agentic system (LangGraph orchestrator, MCP tools)](../readmes/README.AGENTIC_SYSTEM.md)
- [Graph database schema (Neo4j node/edge model)](../readmes/GRAPH.SCHEMA.md) · [Graph DB internals](../readmes/README.GRAPH_DB.md)
- [Webapp](../readmes/README.WEBAPP.md)

## Module & plugin development

- **[Module & plugin development guide](./MODULE_DEVELOPMENT.md)** — how to implement the
  unified [`ModuleContract`](../common/module_contract.py) (Phase 2) and ship a
  validated [`plugin.manifest.json`](../webapp/src/lib/pluginManifest.ts) (Phase 6).
- [MCP integration](../readmes/README.MCP.md)
- [Recon module](../readmes/README.RECON.md) · [Recon orchestrator](../readmes/README.RECON_ORCHESTRATOR.md)
- [Knowledge base / skills](../readmes/README.KBASE.md)

## API reference

- [Recon orchestrator API](../readmes/README.RECON_ORCHESTRATOR.md) — start/stop/state
  endpoints for every scanner, plus the unified `/api/jobs` lifecycle projection.
- [Agentic system endpoints](../readmes/README.AGENTIC_SYSTEM.md) — agent WebSocket,
  `/plugins`, `/plugins/health`, `/recon`-family endpoints.

## Deployment

- [Developer setup](../readmes/README.DEV.md)
- [Postgres](../readmes/README.POSTGRES.md)
- Docker Compose: see `docker-compose.yml` (webapp) and
  `recon_orchestrator/docker-compose.yml` (scanners), walked through in
  [README.DEV.md](../readmes/README.DEV.md).

## Operations & subsystems

- [Memory governor](../readmes/README.MEMORY_GOVERNOR.md)
- [GVM scanning](../readmes/README.GVM.md) · [Vulnerability scan](../readmes/README.VULN_SCAN.md)
- [MITRE enrichment](../readmes/README.MITRE.md) · [Tradecraft](../readmes/README.TRADECRAFT.md)
- [Port scan](../readmes/README.PORT_SCAN.md) · [HTTP probe](../readmes/README.HTTP_PROBE.md) · [Resource enum](../readmes/README.RESOURCE_ENUM.md)

## Troubleshooting

- [Troubleshooting guide](../readmes/TROUBLESHOOTING.md)
