import { NextRequest, NextResponse } from 'next/server'
import { createRequestLogger } from '@/lib/logger'
import { handleWebhook } from '@/lib/subscription/billing'

// POST /api/subscription/webhook — billing-provider webhook sink.
// Stripe: verifies the `stripe-signature` header against STRIPE_WEBHOOK_SECRET.
// Mock:   trusts a JSON body { type:'activate', userId, plan } (dev/self-host).
// Unauthenticated by design — security comes from signature verification.
export async function POST(request: NextRequest) {
  const log = createRequestLogger(request, 'api.subscription.webhook')
  try {
    const rawBody = await request.text()
    const signature = request.headers.get('stripe-signature')
    const result = await handleWebhook(rawBody, signature)
    if (!result.handled) {
      log.info('webhook not handled', { detail: result.detail })
    }
    return NextResponse.json(result, { status: result.handled ? 200 : 202 })
  } catch (error) {
    log.error('webhook error', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Webhook processing failed' }, { status: 400 })
  }
}
