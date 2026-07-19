// Live end-to-end subscription flow against a real database.
// Opt-in (needs a running Postgres) so the default/CI unit run stays DB-free:
//   RUN_DB_TESTS=1 DATABASE_URL=... npx vitest run src/lib/subscription/flow.integration.test.ts
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import prisma from '@/lib/prisma'
import { ensureSubscription, getEntitlements, assertFeature, consumeScan } from './entitlements'
import { startCheckout, cancelSubscription, activatePlan } from './billing'

const RUN_DB_TESTS = process.env.RUN_DB_TESTS === '1'
const EMAIL = `sub-flow-${Date.now()}@test.local`
let userId = ''

describe.skipIf(!RUN_DB_TESTS)('subscription flow (live DB)', () => {
  beforeAll(async () => {
    const u = await prisma.user.create({ data: { name: 'Flow Test', email: EMAIL } })
    userId = u.id
  })

  afterAll(async () => {
    await prisma.subscription.deleteMany({ where: { userId } })
    await prisma.user.deleteMany({ where: { id: userId } })
    await prisma.$disconnect()
  })

  it('new user defaults to the free plan', async () => {
    const sub = await ensureSubscription(userId)
    expect(sub.plan).toBe('free')
    expect(sub.status).toBe('active')
    const ent = await getEntitlements(userId)
    expect(ent.plan).toBe('free')
    expect(ent.usage.scansLimit).toBe(10)
    expect(ent.features).toContain('scan.sast')
    expect(ent.features).not.toContain('export.sarif')
  })

  it('gates a premium feature on the free plan', async () => {
    const denied = await assertFeature(userId, 'export.sarif')
    expect(typeof denied).toBe('string') // a denial reason
    const allowed = await assertFeature(userId, 'scan.sast')
    expect(allowed).toBeNull()
  })

  it('meters scans and blocks past the free quota (no negative response)', async () => {
    // consume the 10 free scans
    for (let i = 0; i < 10; i++) {
      const r = await consumeScan(userId)
      expect(r.ok).toBe(true)
    }
    // 11th is refused with a reason — not an exception, not a negative number
    const over = await consumeScan(userId)
    expect(over.ok).toBe(false)
    expect(over.reason).toMatch(/limit/i)
    const ent = await getEntitlements(userId)
    expect(ent.usage.scansUsed).toBe(10)
    expect(ent.usage.scansRemaining).toBe(0) // clamped at 0, never negative
  })

  it('upgrade to Pro (mock checkout) unlocks features and raises the quota', async () => {
    const checkout = await startCheckout(userId, EMAIL, 'pro', 'monthly')
    expect(checkout.activated).toBe(true) // mock mode activates immediately
    const ent = await getEntitlements(userId)
    expect(ent.plan).toBe('pro')
    expect(ent.usage.scansLimit).toBe(500)
    expect(ent.usage.scansUsed).toBe(0) // usage reset on activation
    expect(ent.features).toContain('export.sarif')
    expect(await assertFeature(userId, 'export.sarif')).toBeNull()
    // and scanning works again
    expect((await consumeScan(userId)).ok).toBe(true)
  })

  it('upgrade to Team makes scans unlimited', async () => {
    await activatePlan(userId, 'team')
    const ent = await getEntitlements(userId)
    expect(ent.plan).toBe('team')
    expect(ent.usage.scansLimit).toBe(-1)          // unlimited sentinel
    expect(ent.usage.scansRemaining).toBe(-1)
    expect((await consumeScan(userId)).ok).toBe(true)
  })

  it('cancel keeps access until period end', async () => {
    await cancelSubscription(userId)
    const ent = await getEntitlements(userId)
    expect(ent.cancelAtPeriodEnd).toBe(true)
    expect(ent.plan).toBe('team') // still active until period end
  })

  it('immediate cancel reverts to free', async () => {
    await cancelSubscription(userId, true)
    const ent = await getEntitlements(userId)
    expect(ent.plan).toBe('free')
    expect(ent.cancelAtPeriodEnd).toBe(false)
  })
})
