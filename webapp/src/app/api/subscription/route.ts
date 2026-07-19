import { NextRequest, NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { createRequestLogger } from '@/lib/logger'
import { getEntitlements } from '@/lib/subscription/entitlements'
import { billingMode } from '@/lib/subscription/billing'
import { PLANS, PLAN_ORDER } from '@/lib/subscription/plans'

// GET /api/subscription — the signed-in user's current plan, usage, and the
// full plan catalogue (so the pricing UI and billing page share one source).
export async function GET(request: NextRequest) {
  const log = createRequestLogger(request, 'api.subscription')
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  try {
    const entitlements = await getEntitlements(session.userId)
    return NextResponse.json({
      entitlements,
      billingMode: billingMode(),
      plans: PLAN_ORDER.map((id) => PLANS[id]),
    })
  } catch (error) {
    log.error('failed to load subscription', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to load subscription' }, { status: 500 })
  }
}
