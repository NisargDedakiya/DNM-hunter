import { NextRequest, NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { createRequestLogger } from '@/lib/logger'
import { consumeScan, assertFeature, getEntitlements } from '@/lib/subscription/entitlements'
import type { Feature } from '@/lib/subscription/plans'

// POST /api/subscription/consume  { feature?: Feature }
// The metering gate a scan-launch flow calls before starting work:
//  - checks the optional feature is in the user's plan (403 if not),
//  - atomically consumes one scan against the monthly quota (402 if exhausted).
// Returns the refreshed entitlements so callers can update usage UI.
export async function POST(request: NextRequest) {
  const log = createRequestLogger(request, 'api.subscription.consume')
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  try {
    const body = await request.json().catch(() => ({}))
    const feature: Feature | undefined = body?.feature

    if (feature) {
      const denied = await assertFeature(session.userId, feature)
      if (denied) {
        return NextResponse.json({ ok: false, reason: denied, code: 'feature_locked' }, { status: 403 })
      }
    }

    const result = await consumeScan(session.userId)
    if (!result.ok) {
      return NextResponse.json({ ok: false, reason: result.reason, code: 'quota_exceeded' }, { status: 402 })
    }

    const entitlements = await getEntitlements(session.userId)
    return NextResponse.json({ ok: true, entitlements })
  } catch (error) {
    log.error('consume failed', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to record usage' }, { status: 500 })
  }
}
