import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireSession } from '@/lib/session'
import { createRequestLogger } from '@/lib/logger'

// GET /api/hunt/programs — the signed-in user's programs (id + name), for the
// "Track as submission" program picker. Session-scoped (no userId param).
export async function GET(request: NextRequest) {
  const log = createRequestLogger(request, 'api.hunt.programs')
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  try {
    const programs = await prisma.program.findMany({
      where: { userId: session.userId },
      orderBy: { createdAt: 'desc' },
      select: { id: true, name: true, platform: true },
    })
    return NextResponse.json(programs)
  } catch (error) {
    log.error('failed to list programs', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to list programs' }, { status: 500 })
  }
}
