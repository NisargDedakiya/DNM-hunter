/**
 * Guards that every manifest actually shipped under plugins/ validates against
 * the schema (master-plan Phase 6). A malformed manifest fails CI here rather
 * than silently breaking the catalog loader at runtime.
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { validateManifest } from './pluginManifest'

// webapp/src/lib -> repo root -> plugins/
const PLUGINS_DIR = join(process.cwd(), '..', 'plugins')
const CATEGORIES = ['recon', 'scanner', 'validator', 'reporter', 'export']

function allManifestPaths(): string[] {
  const paths: string[] = []
  for (const cat of CATEGORIES) {
    let entries: string[] = []
    try { entries = readdirSync(join(PLUGINS_DIR, cat)) } catch { continue }
    for (const f of entries) if (f.endsWith('.json')) paths.push(join(PLUGINS_DIR, cat, f))
  }
  return paths
}

describe('shipped plugin manifests', () => {
  const paths = allManifestPaths()

  test('there are manifests to validate', () => {
    expect(paths.length).toBeGreaterThan(0)
  })

  test.each(paths)('%s validates against the manifest schema', (p) => {
    const raw = JSON.parse(readFileSync(p, 'utf-8'))
    const res = validateManifest(raw)
    expect(res.errors).toEqual([])
    expect(res.ok).toBe(true)
  })

  test('the nuclei + katana reference plugins declare permissions', () => {
    for (const id of ['nuclei', 'katana']) {
      const p = paths.find(x => x.endsWith(`${id}.json`))!
      const res = validateManifest(JSON.parse(readFileSync(p, 'utf-8')))
      expect(res.manifest?.permissions.length).toBeGreaterThan(0)
      expect(res.manifest?.moduleContractEntrypoint).toBeTruthy()
    }
  })
})
