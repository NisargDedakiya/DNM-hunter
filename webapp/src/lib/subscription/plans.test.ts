import { describe, it, expect } from 'vitest'
import {
  PLANS, PLAN_ORDER, getPlan, planHasFeature, isUpgrade, priceFor, isUnlimited, UNLIMITED,
} from './plans'
import {
  needsUsageReset, effectiveScansUsed, canRunScan, hasFeature, toEntitlements, type UsageState,
} from './entitlements'

function usage(overrides: Partial<UsageState> = {}): UsageState {
  return {
    plan: 'free', status: 'active', scansUsed: 0, seatsUsed: 1,
    usageResetAt: new Date(), currentPeriodEnd: null, cancelAtPeriodEnd: false,
    ...overrides,
  }
}

describe('plans catalogue', () => {
  it('has three ordered tiers', () => {
    expect(PLAN_ORDER).toEqual(['free', 'pro', 'team'])
    expect(Object.keys(PLANS).sort()).toEqual(['free', 'pro', 'team'])
  })

  it('free is limited; pro/team unlock more', () => {
    expect(PLANS.free.limits.scansPerMonth).toBe(10)
    expect(PLANS.pro.features).toContain('export.sarif')
    expect(PLANS.free.features).not.toContain('export.sarif')
    expect(isUnlimited(PLANS.team.limits.scansPerMonth)).toBe(true)
  })

  it('getPlan falls back to free on unknown id', () => {
    expect(getPlan('bogus').id).toBe('free')
    expect(getPlan(null).id).toBe('free')
  })

  it('planHasFeature gates correctly', () => {
    expect(planHasFeature('pro', 'scan.smart_contract')).toBe(true)
    expect(planHasFeature('free', 'scan.smart_contract')).toBe(false)
  })

  it('isUpgrade compares tiers', () => {
    expect(isUpgrade('free', 'pro')).toBe(true)
    expect(isUpgrade('team', 'pro')).toBe(false)
  })

  it('priceFor returns cycle price', () => {
    expect(priceFor('pro', 'monthly').amount).toBe(49)
    expect(priceFor('pro', 'yearly').amount).toBe(39)
    expect(priceFor('pro', 'yearly').billedYearlyTotal).toBe(39 * 12)
  })
})

describe('entitlements / quota', () => {
  it('needsUsageReset after 30 days', () => {
    const old = new Date(Date.now() - 31 * 24 * 3600 * 1000)
    expect(needsUsageReset({ usageResetAt: old })).toBe(true)
    expect(needsUsageReset({ usageResetAt: new Date() })).toBe(false)
  })

  it('effectiveScansUsed resets after period lapse', () => {
    const old = new Date(Date.now() - 31 * 24 * 3600 * 1000)
    expect(effectiveScansUsed(usage({ scansUsed: 8, usageResetAt: old }))).toBe(0)
    expect(effectiveScansUsed(usage({ scansUsed: 8 }))).toBe(8)
  })

  it('canRunScan enforces the free limit', () => {
    expect(canRunScan(usage({ scansUsed: 9 }))).toBe(true)
    expect(canRunScan(usage({ scansUsed: 10 }))).toBe(false)
  })

  it('canRunScan is unlimited on team', () => {
    expect(canRunScan(usage({ plan: 'team', scansUsed: 99999 }))).toBe(true)
  })

  it('canceled subscription cannot scan', () => {
    expect(canRunScan(usage({ plan: 'pro', status: 'canceled' }))).toBe(false)
  })

  it('hasFeature reflects the plan', () => {
    expect(hasFeature(usage({ plan: 'pro' }), 'export.sarif')).toBe(true)
    expect(hasFeature(usage({ plan: 'free' }), 'export.sarif')).toBe(false)
  })

  it('toEntitlements computes remaining and limits', () => {
    const ent = toEntitlements(usage({ plan: 'free', scansUsed: 3 }))
    expect(ent.plan).toBe('free')
    expect(ent.usage.scansLimit).toBe(10)
    expect(ent.usage.scansRemaining).toBe(7)
    const team = toEntitlements(usage({ plan: 'team', scansUsed: 500 }))
    expect(team.usage.scansRemaining).toBe(-1) // unlimited sentinel
  })

  it('UNLIMITED sentinel is -1', () => {
    expect(UNLIMITED).toBe(-1)
  })
})
