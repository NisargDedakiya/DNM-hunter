import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { hashApiToken } from '@/lib/apiTokens'

/**
 * POST /api/auth/verify-api-token — internal-only. Called by middleware.ts
 * (never by a browser) to resolve a Bearer token to a user, keeping the
 * Prisma hash lookup out of the Edge-runtime middleware itself. Requests
 * reach this route handler only after middleware's own X-Internal-Key check
 * has already passed the request through, so no additional auth check is
 * needed here — but this route is deliberately NOT in middleware's
 * PUBLIC_PATHS, so a request without a valid X-Internal-Key is rejected by
 * middleware before it ever gets here.
 */
export async function POST(request: NextRequest) {
  try {
    const { token } = await request.json()
    if (!token || typeof token !== 'string') {
      return NextResponse.json({ error: 'token is required' }, { status: 400 })
    }

    const tokenHash = hashApiToken(token)
    const record = await prisma.apiToken.findUnique({
      where: { tokenHash },
      select: { id: true, userId: true, revokedAt: true, expiresAt: true, user: { select: { role: true } } },
    })

    if (!record || record.revokedAt) {
      return NextResponse.json({ error: 'Invalid token' }, { status: 401 })
    }
    if (record.expiresAt && record.expiresAt.getTime() < Date.now()) {
      return NextResponse.json({ error: 'Token expired' }, { status: 401 })
    }

    // Best-effort; a failed write here shouldn't block the request.
    prisma.apiToken.update({ where: { id: record.id }, data: { lastUsedAt: new Date() } }).catch(() => {})

    return NextResponse.json({ userId: record.userId, role: record.user.role })
  } catch (error) {
    console.error('Verify API token failed:', error)
    return NextResponse.json({ error: 'Verification failed' }, { status: 500 })
  }
}
