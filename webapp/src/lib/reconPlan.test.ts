import { describe, test, expect } from 'vitest'
import { buildReconPlan, MODULE_CATALOG } from './reconPlan'

describe('buildReconPlan', () => {
  test('only references modules that exist in the catalog', () => {
    const known = new Set(MODULE_CATALOG.map(m => m.name))
    const plan = buildReconPlan([], ['acme.com'])
    for (const step of plan.steps) expect(known.has(step.moduleName)).toBe(true)
  })

  test('technology match is prioritized high with an explaining rationale', () => {
    const plan = buildReconPlan(['terraform'], ['repo'])
    const iac = plan.steps.find(s => s.moduleName === 'iac_scan')!
    expect(iac.priority).toBe('high')
    expect(iac.rationale.toLowerCase()).toContain('terraform')
  })

  test('with no tech signal, recon is medium (not scanner-low)', () => {
    const plan = buildReconPlan([], ['acme.com'])
    const recon = plan.steps.find(s => s.moduleName === 'recon')!
    expect(recon.priority).toBe('medium')
  })

  test('steps are ordered high-priority first', () => {
    const plan = buildReconPlan(['graphql'], ['acme.com'])
    const rank = { high: 0, medium: 1, low: 2 } as const
    const seq = plan.steps.map(s => rank[s.priority])
    expect(seq).toEqual([...seq].sort((a, b) => a - b))
  })

  test('assets propagate to every step', () => {
    const plan = buildReconPlan([], ['a.com', 'b.com'])
    for (const s of plan.steps) expect(s.targetAssets).toEqual(['a.com', 'b.com'])
  })

  test('reasoning mentions detected technology', () => {
    const plan = buildReconPlan(['WordPress'], ['acme.com'])
    expect(plan.reasoning.toLowerCase()).toContain('wordpress')
  })
})
