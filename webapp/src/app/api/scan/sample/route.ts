import { NextResponse } from 'next/server'
import { sampleScanPayload } from '@/lib/scan/sample'

// GET /api/scan/sample — a public, no-auth demo scan so a prospect can see the
// product's output before signing up. Static content; safe to cache.
export async function GET() {
  return NextResponse.json(sampleScanPayload(), {
    headers: { 'Cache-Control': 'public, max-age=3600' },
  })
}
