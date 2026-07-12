// Plugin manifest schema + validator (master-plan Phase 6, Priority 12).
//
// Turns the loose plugins/*/*.json metadata into a validated, installable-module
// contract. The schema is a SUPERSET of the existing catalog shape — the legacy
// fields (id/name/category/kind/description/status/tags) stay required so every
// current manifest keeps validating, while the new capability fields
// (moduleContractEntrypoint, requiredTools, configSchema, permissions,
// compatibility) are optional so richer plugins can declare them incrementally.
//
// Security-first: a plugin executes security tools, so its declared permissions
// (network reach, scope needs) are first-class and shown before enabling. The
// loader enforces them against the existing RoE hard-guardrail — a manifest can
// never widen what a plugin is allowed to touch.

import { z } from 'zod'

export const PLUGIN_CATEGORIES = ['recon', 'scanner', 'validator', 'reporter', 'export'] as const
export const PLUGIN_KINDS = ['mcp-server', 'builtin', 'webapp-subsystem'] as const
export const PLUGIN_STATUS = ['core', 'community'] as const

// A network permission the operator must see before enabling a plugin.
export const PermissionSchema = z.object({
  // e.g. "network:target", "network:internet", "scope:in-scope-only", "fs:read"
  scope: z.string().min(1),
  reason: z.string().default(''),
})
export type PluginPermission = z.infer<typeof PermissionSchema>

export const PluginManifestSchema = z.object({
  // ── Legacy catalog fields (kept required for backward compatibility) ──
  id: z.string().min(1),
  name: z.string().min(1),
  category: z.enum(PLUGIN_CATEGORIES),
  kind: z.enum(PLUGIN_KINDS),
  description: z.string().default(''),
  dockerService: z.string().nullable().default(null),
  mcpPort: z.number().int().positive().optional(),
  status: z.enum(PLUGIN_STATUS).default('community'),
  tags: z.array(z.string()).default([]),

  // ── Installable-module fields (master-plan Phase 6, all optional) ──
  version: z.string().optional(),
  author: z.string().optional(),
  // The ModuleContract entrypoint (Phase 2) this plugin implements, e.g.
  // "common.adapters.builtin_adapters:ReconAdapter".
  moduleContractEntrypoint: z.string().optional(),
  requiredTools: z.array(z.string()).default([]),
  // JSON Schema for this plugin's config (kept as a passthrough object).
  configSchema: z.record(z.string(), z.unknown()).optional(),
  permissions: z.array(PermissionSchema).default([]),
  compatibility: z.object({
    minPlatformVersion: z.string().optional(),
  }).optional(),
})

export type PluginManifest = z.infer<typeof PluginManifestSchema>

export interface ManifestValidation {
  ok: boolean
  manifest: PluginManifest | null
  errors: string[]
}

// Validate one manifest object. Never throws — returns a structured result so a
// single bad manifest can be surfaced in the UI rather than breaking the loader.
export function validateManifest(raw: unknown): ManifestValidation {
  const parsed = PluginManifestSchema.safeParse(raw)
  if (parsed.success) {
    return { ok: true, manifest: parsed.data, errors: [] }
  }
  return {
    ok: false,
    manifest: null,
    errors: parsed.error.issues.map(i => `${i.path.join('.') || '(root)'}: ${i.message}`),
  }
}

// True when a plugin needs network access to the target/internet — used by the
// UI to warn before enabling, and by the loader to check against the RoE.
export function requiresNetwork(m: PluginManifest): boolean {
  return m.kind === 'mcp-server' || m.permissions.some(p => p.scope.startsWith('network:'))
}
