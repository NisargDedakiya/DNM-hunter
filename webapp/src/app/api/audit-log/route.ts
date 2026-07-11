import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { hasPermission } from '@/lib/rbac'
import { createRequestLogger } from '@/lib/logger'

/**
 * GET /api/audit-log?limit=100 — global security/activity log, gated on the
 * audit_log.view permission (admin-only today, see lib/rbac.ts).
 * Reads the x-user-role header middleware.ts injects for every
 * authenticated request (cookie session OR Phase 12 Bearer API token),
 * rather than session.ts's cookie-only getSession() helper, so this stays
 * consistent for both auth paths. middleware.ts already enforces this
 * centrally (lib/rbac.ts ROUTE_PERMISSIONS); this is defense-in-depth.
 */
export async function GET(request: NextRequest) {
  const log = createRequestLogger(request, 'api.audit-log')
  const role = request.headers.get('x-user-role') || ''
  if (!hasPermission(role, 'audit_log.view')) {
    log.warn('audit log access denied', { role })
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }

  try {
    const limitParam = request.nextUrl.searchParams.get('limit')
    const limit = Math.min(Math.max(parseInt(limitParam || '100', 10) || 100, 1), 500)

    const logs = await prisma.auditLog.findMany({
      orderBy: { createdAt: 'desc' },
      take: limit,
      include: { user: { select: { id: true, name: true, email: true } } },
    })
    return NextResponse.json(logs)
  } catch (error) {
    log.error('fetch audit log failed', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to fetch audit log' }, { status: 500 })
  }
}
