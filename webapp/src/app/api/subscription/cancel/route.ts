import { NextRequest, NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { createRequestLogger } from '@/lib/logger'
import { cancelSubscription } from '@/lib/subscription/billing'
import { getEntitlements } from '@/lib/subscription/entitlements'

// POST /api/subscription/cancel  { immediate?: boolean }
// Default: keep paid access until the period ends, then revert to free.
export async function POST(request: NextRequest) {
  const log = createRequestLogger(request, 'api.subscription.cancel')
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  try {
    const body = await request.json().catch(() => ({}))
    await cancelSubscription(session.userId, body?.immediate === true)
    const entitlements = await getEntitlements(session.userId)
    return NextResponse.json({ ok: true, entitlements })
  } catch (error) {
    log.error('cancel failed', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Cancel failed' }, { status: 500 })
  }
}
