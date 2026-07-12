import { describe, test, expect } from 'vitest'
import { validateManifest, requiresNetwork, type PluginManifest } from './pluginManifest'

// A legacy catalog entry (the shape every existing plugins/*.json uses).
const legacy = {
  id: 'nuclei', name: 'Nuclei', category: 'scanner', kind: 'mcp-server',
  description: 'Templated vulnerability scanning.', dockerService: 'kali-sandbox',
  mcpPort: 8002, status: 'core', tags: ['cve'],
}

describe('validateManifest', () => {
  test('accepts an existing legacy manifest unchanged (backward compatible)', () => {
    const res = validateManifest(legacy)
    expect(res.ok).toBe(true)
    expect(res.manifest?.id).toBe('nuclei')
    expect(res.manifest?.permissions).toEqual([])   // defaulted
  })

  test('accepts a rich Phase-6 manifest with permissions + entrypoint', () => {
    const res = validateManifest({
      ...legacy,
      version: '1.0.0', author: 'core',
      moduleContractEntrypoint: 'common.adapters.builtin_adapters:ReconAdapter',
      requiredTools: ['nuclei'],
      permissions: [{ scope: 'network:target', reason: 'sends probes to in-scope hosts' }],
      compatibility: { minPlatformVersion: '2.0.0' },
    })
    expect(res.ok).toBe(true)
    expect(res.manifest?.permissions).toHaveLength(1)
  })

  test('rejects an unknown category with a readable error', () => {
    const res = validateManifest({ ...legacy, category: 'bogus' })
    expect(res.ok).toBe(false)
    expect(res.errors.join(' ')).toContain('category')
  })

  test('rejects a manifest missing required id/name', () => {
    const res = validateManifest({ category: 'scanner', kind: 'builtin' })
    expect(res.ok).toBe(false)
    expect(res.errors.some(e => e.startsWith('id'))).toBe(true)
  })

  test('never throws on garbage input', () => {
    expect(() => validateManifest(null)).not.toThrow()
    expect(validateManifest(42).ok).toBe(false)
  })
})

describe('requiresNetwork', () => {
  test('mcp-server plugins require network', () => {
    expect(requiresNetwork(validateManifest(legacy).manifest as PluginManifest)).toBe(true)
  })

  test('a builtin with a network permission requires network', () => {
    const m = validateManifest({ ...legacy, kind: 'builtin', dockerService: null, mcpPort: undefined, permissions: [{ scope: 'network:internet', reason: 'x' }] }).manifest as PluginManifest
    expect(requiresNetwork(m)).toBe(true)
  })

  test('a pure builtin with no network permission does not', () => {
    const m = validateManifest({ ...legacy, kind: 'builtin', dockerService: null, mcpPort: undefined }).manifest as PluginManifest
    expect(requiresNetwork(m)).toBe(false)
  })
})
