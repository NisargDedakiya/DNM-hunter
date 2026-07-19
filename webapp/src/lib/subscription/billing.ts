// Billing provider abstraction. Two modes:
//
//   mock   (default) — no external dependency. A "checkout" activates the plan
//                       immediately and returns an in-app URL. Ideal for
//                       self-hosted / on-prem / development.
//   stripe (when STRIPE_SECRET_KEY is set) — creates a real Stripe Checkout
//                       session. The `stripe` package is imported dynamically
//                       and only if present, so it is never a build-time
//                       dependency of the app.

import prisma from '@/lib/prisma'
import { nextResetDate } from './entitlements'
import { getPlan, type PlanId } from './plans'

export type BillingMode = 'mock' | 'stripe'
export type BillingCycle = 'monthly' | 'yearly'

export function billingMode(): BillingMode {
  return process.env.STRIPE_SECRET_KEY ? 'stripe' : 'mock'
}

export interface CheckoutResult {
  url: string
  mode: BillingMode
  /** true when the plan was activated immediately (mock mode). */
  activated: boolean
}

const APP_URL = () => process.env.APP_URL || process.env.NEXT_PUBLIC_APP_URL || ''

/** Activate (or change) a user's plan directly — used by mock checkout and by
 * verified provider webhooks. */
export async function activatePlan(
  userId: string,
  plan: PlanId,
  opts: { cycle?: BillingCycle; externalCustomerId?: string; externalSubscriptionId?: string; provider?: BillingMode } = {},
) {
  const now = new Date()
  const isFree = plan === 'free'
  return prisma.subscription.upsert({
    where: { userId },
    create: {
      userId,
      plan,
      status: 'active',
      billingProvider: opts.provider ?? billingMode(),
      externalCustomerId: opts.externalCustomerId ?? null,
      externalSubscriptionId: opts.externalSubscriptionId ?? null,
      currentPeriodStart: now,
      currentPeriodEnd: isFree ? null : nextResetDate(now),
      scansUsed: 0,
      usageResetAt: now,
    },
    update: {
      plan,
      status: 'active',
      cancelAtPeriodEnd: false,
      billingProvider: opts.provider ?? billingMode(),
      externalCustomerId: opts.externalCustomerId ?? undefined,
      externalSubscriptionId: opts.externalSubscriptionId ?? undefined,
      currentPeriodStart: now,
      currentPeriodEnd: isFree ? null : nextResetDate(now),
    },
  })
}

/** Start a checkout for `plan`. In mock mode this activates immediately. */
export async function startCheckout(
  userId: string,
  userEmail: string,
  plan: PlanId,
  cycle: BillingCycle,
): Promise<CheckoutResult> {
  if (plan === 'free') {
    await activatePlan(userId, 'free')
    return { url: '/settings/billing?downgraded=1', mode: billingMode(), activated: true }
  }

  if (billingMode() === 'mock') {
    await activatePlan(userId, plan, { cycle, provider: 'mock' })
    return { url: `/settings/billing?upgraded=${plan}`, mode: 'mock', activated: true }
  }

  // Stripe mode — dynamic, guarded import so `stripe` is never required to
  // build. The package is optional, so it is loaded and typed as `any`.
  try {
    const mod: any = await loadStripe()
    if (!mod) throw new Error('stripe package not installed')
    const Stripe = mod.default
    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY as string)
    const priceId = priceIdFor(plan, cycle)
    if (!priceId) throw new Error(`no Stripe price configured for ${plan}/${cycle}`)
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer_email: userEmail || undefined,
      line_items: [{ price: priceId, quantity: 1 }],
      client_reference_id: userId,
      metadata: { userId, plan, cycle },
      success_url: `${APP_URL()}/settings/billing?upgraded=${plan}`,
      cancel_url: `${APP_URL()}/pricing?canceled=1`,
    })
    return { url: session.url ?? '/pricing', mode: 'stripe', activated: false }
  } catch (err) {
    // Never hard-fail the request on a billing misconfiguration; surface it.
    throw new Error(`stripe checkout failed: ${err instanceof Error ? err.message : String(err)}`)
  }
}

/** Cancel: keep access until period end, then revert to free. */
export async function cancelSubscription(userId: string, immediate = false) {
  if (immediate) {
    return activatePlan(userId, 'free')
  }
  return prisma.subscription.update({
    where: { userId },
    data: { cancelAtPeriodEnd: true },
  })
}

// Maps a plan+cycle to a Stripe Price id from env (only used in stripe mode).
function priceIdFor(plan: PlanId, cycle: BillingCycle): string | undefined {
  const key = `STRIPE_PRICE_${plan.toUpperCase()}_${cycle.toUpperCase()}`
  return process.env[key]
}

/** Verify + interpret a provider webhook. Mock mode trusts the JSON body. */
export async function handleWebhook(rawBody: string, signature: string | null): Promise<{ handled: boolean; detail: string }> {
  if (billingMode() === 'mock') {
    const evt = JSON.parse(rawBody || '{}')
    if (evt.type === 'activate' && evt.userId && evt.plan) {
      await activatePlan(evt.userId, evt.plan, { provider: 'mock' })
      return { handled: true, detail: `mock: activated ${evt.plan} for ${evt.userId}` }
    }
    return { handled: false, detail: 'mock: ignored event' }
  }

  const mod: any = await loadStripe()
  if (!mod) return { handled: false, detail: 'stripe package not installed' }
  const Stripe = mod.default
  const stripe = new Stripe(process.env.STRIPE_SECRET_KEY as string)
  const secret = process.env.STRIPE_WEBHOOK_SECRET
  if (!secret || !signature) return { handled: false, detail: 'missing webhook secret/signature' }

  let event: any
  try {
    event = stripe.webhooks.constructEvent(rawBody, signature, secret)
  } catch (err) {
    return { handled: false, detail: `signature verification failed: ${err instanceof Error ? err.message : err}` }
  }

  switch (event.type) {
    case 'checkout.session.completed': {
      const s = event.data.object
      const userId: string | undefined = s.client_reference_id || s.metadata?.userId
      const plan = (s.metadata?.plan as PlanId) || 'pro'
      if (userId) {
        await activatePlan(userId, getPlan(plan).id, {
          provider: 'stripe',
          externalCustomerId: (s.customer as string) ?? undefined,
          externalSubscriptionId: (s.subscription as string) ?? undefined,
        })
        return { handled: true, detail: `activated ${plan} for ${userId}` }
      }
      return { handled: false, detail: 'no userId on session' }
    }
    case 'customer.subscription.deleted': {
      const sub = event.data.object
      const row = await prisma.subscription.findFirst({ where: { externalSubscriptionId: sub.id } })
      if (row) {
        await activatePlan(row.userId, 'free')
        return { handled: true, detail: `reverted ${row.userId} to free` }
      }
      return { handled: false, detail: 'no matching subscription' }
    }
    default:
      return { handled: false, detail: `unhandled event ${event.type}` }
  }
}

// Optional dependency loader — resolved at runtime; typed as `any` so `stripe`
// is never a compile-time dependency. `webpackIgnore` keeps the bundler from
// trying to resolve the module at build time.
async function loadStripe(): Promise<any> {
  try {
    // Indirect specifier so TypeScript/bundler never resolve `stripe` at build
    // time — it is a purely optional runtime dependency.
    const mod = 'stripe'
    const dynamicImport = new Function('m', 'return import(m)') as (m: string) => Promise<any>
    return await dynamicImport(mod)
  } catch {
    return null
  }
}
