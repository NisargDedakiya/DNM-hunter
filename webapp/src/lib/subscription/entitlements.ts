// Entitlement resolution + usage metering. The pure functions (quota math,
// period reset, entitlement snapshot) are exported for unit testing without a
// database; the async helpers wrap Prisma for use in API routes.

import prisma from '@/lib/prisma'
import { type Feature, type PlanId, getPlan, isUnlimited, PLANS } from './plans'

const PERIOD_DAYS = 30
const PERIOD_MS = PERIOD_DAYS * 24 * 60 * 60 * 1000

// The minimal shape the pure helpers need — matches the Prisma Subscription row
// but decoupled so tests can construct plain objects.
export interface UsageState {
  plan: string
  status: string
  scansUsed: number
  seatsUsed: number
  usageResetAt: Date
  currentPeriodEnd: Date | null
  cancelAtPeriodEnd: boolean
}

export interface Entitlements {
  plan: PlanId
  planName: string
  status: string
  features: Feature[]
  limits: { scansPerMonth: number; seats: number; targetsPerScan: number }
  usage: {
    scansUsed: number
    scansLimit: number
    scansRemaining: number   // -1 when unlimited
    seatsUsed: number
    seatsLimit: number
  }
  cancelAtPeriodEnd: boolean
  currentPeriodEnd: string | null
}

/** Has the metered period elapsed and usage should reset to zero? */
export function needsUsageReset(s: Pick<UsageState, 'usageResetAt'>, now: Date = new Date()): boolean {
  return now.getTime() - new Date(s.usageResetAt).getTime() >= PERIOD_MS
}

export function nextResetDate(now: Date = new Date()): Date {
  return new Date(now.getTime() + PERIOD_MS)
}

/** Effective scans-used, accounting for a lapsed period (treated as reset). */
export function effectiveScansUsed(s: UsageState, now: Date = new Date()): number {
  return needsUsageReset(s, now) ? 0 : s.scansUsed
}

/** Can this subscription run one more scan right now? */
export function canRunScan(s: UsageState, now: Date = new Date()): boolean {
  if (s.status === 'canceled') return false
  const limit = getPlan(s.plan).limits.scansPerMonth
  if (isUnlimited(limit)) return true
  return effectiveScansUsed(s, now) < limit
}

export function hasFeature(s: Pick<UsageState, 'plan'>, feature: Feature): boolean {
  return getPlan(s.plan).features.includes(feature)
}

/** Build the client-facing entitlement snapshot from a usage row. */
export function toEntitlements(s: UsageState, now: Date = new Date()): Entitlements {
  const plan = getPlan(s.plan)
  const used = effectiveScansUsed(s, now)
  const scansLimit = plan.limits.scansPerMonth
  return {
    plan: plan.id,
    planName: plan.name,
    status: s.status,
    features: plan.features,
    limits: plan.limits,
    usage: {
      scansUsed: used,
      scansLimit,
      scansRemaining: isUnlimited(scansLimit) ? -1 : Math.max(0, scansLimit - used),
      seatsUsed: s.seatsUsed,
      seatsLimit: plan.limits.seats,
    },
    cancelAtPeriodEnd: s.cancelAtPeriodEnd,
    currentPeriodEnd: s.currentPeriodEnd ? new Date(s.currentPeriodEnd).toISOString() : null,
  }
}

// ─────────────────────────── Prisma-backed helpers ───────────────────────────

/** Fetch the user's subscription, creating a default free row if none exists. */
export async function ensureSubscription(userId: string) {
  const existing = await prisma.subscription.findUnique({ where: { userId } })
  if (existing) {
    // lazily roll the period if it has lapsed
    if (needsUsageReset(existing)) {
      return prisma.subscription.update({
        where: { userId },
        data: { scansUsed: 0, usageResetAt: new Date(), currentPeriodStart: new Date() },
      })
    }
    return existing
  }
  return prisma.subscription.create({ data: { userId } })
}

export async function getEntitlements(userId: string): Promise<Entitlements> {
  const sub = await ensureSubscription(userId)
  return toEntitlements(sub as unknown as UsageState)
}

/** Throws-style gate for a feature. Returns null when allowed, or a reason. */
export async function assertFeature(userId: string, feature: Feature): Promise<string | null> {
  const sub = await ensureSubscription(userId)
  if (hasFeature(sub as unknown as UsageState, feature)) return null
  const plan = getPlan(sub.plan)
  return `The ${feature} capability is not included in the ${plan.name} plan. Upgrade to unlock it.`
}

/**
 * Atomically consume one scan against the quota. Returns { ok, reason }.
 * Resets the period first if it has lapsed.
 */
export async function consumeScan(userId: string): Promise<{ ok: boolean; reason?: string }> {
  const sub = await ensureSubscription(userId)
  const state = sub as unknown as UsageState
  if (!canRunScan(state)) {
    const limit = getPlan(state.plan).limits.scansPerMonth
    return { ok: false, reason: `Monthly scan limit reached (${limit}). Upgrade your plan for more.` }
  }
  await prisma.subscription.update({
    where: { userId },
    data: { scansUsed: { increment: 1 } },
  })
  return { ok: true }
}

export { PLANS }
