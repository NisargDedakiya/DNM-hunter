import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireSession } from '@/lib/session'
import { createRequestLogger } from '@/lib/logger'
import { startCheckout, type BillingCycle } from '@/lib/subscription/billing'
import { isPlanId } from '@/lib/subscription/plans'

// POST /api/subscription/checkout  { plan: 'pro'|'team'|'free', cycle?: 'monthly'|'yearly' }
// In mock mode the plan is activated immediately and `url` points back into the
// app; in Stripe mode `url` is a hosted Checkout session to redirect to.
export async function POST(request: NextRequest) {
  const log = createRequestLogger(request, 'api.subscription.checkout')
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  try {
    const body = await request.json().catch(() => ({}))
    const plan = body?.plan
    const cycle: BillingCycle = body?.cycle === 'yearly' ? 'yearly' : 'monthly'
    if (!isPlanId(plan)) {
      return NextResponse.json({ error: 'Invalid plan' }, { status: 400 })
    }
    const user = await prisma.user.findUnique({ where: { id: session.userId }, select: { email: true } })
    const result = await startCheckout(session.userId, user?.email ?? '', plan, cycle)
    return NextResponse.json(result)
  } catch (error) {
    log.error('checkout failed', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: error instanceof Error ? error.message : 'Checkout failed' }, { status: 500 })
  }
}
