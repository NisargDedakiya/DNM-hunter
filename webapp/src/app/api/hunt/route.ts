import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireSession } from '@/lib/session'
import { createRequestLogger } from '@/lib/logger'
import { getEntitlements } from '@/lib/subscription/entitlements'
import { computeHunterStats } from '@/lib/hunt/stats'

// GET /api/hunt — the bug hunter's cross-program cockpit: every submission in
// one pipeline, plus the aggregate stats. Earnings analytics are a paid feature
// ('hunt.earnings'); when the plan lacks it, the earnings numbers are withheld
// and `earningsLocked` is set so the UI can show an upgrade nudge.
export async function GET(request: NextRequest) {
  const log = createRequestLogger(request, 'api.hunt')
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  try {
    const ent = await getEntitlements(session.userId)

    // submissions across all programs the user owns
    const programs = await prisma.program.findMany({
      where: { userId: session.userId },
      select: { id: true, name: true, platform: true },
    })
    const programMap = new Map(programs.map((p) => [p.id, p]))
    const submissions = await prisma.submission.findMany({
      where: { programId: { in: programs.map((p) => p.id) } },
      orderBy: { createdAt: 'desc' },
      take: 200,
    })

    const rows = submissions.map((s) => ({
      id: s.id,
      programId: s.programId,
      programName: programMap.get(s.programId)?.name ?? '—',
      title: s.title,
      severity: s.severity,
      status: s.status,
      platform: s.platform ?? programMap.get(s.programId)?.platform ?? null,
      bounty: s.bounty,
      submittedAt: s.submittedAt,
      createdAt: s.createdAt,
    }))

    const stats = computeHunterStats(submissions)
    const earningsLocked = !ent.features.includes('hunt.earnings')

    return NextResponse.json({
      programCount: programs.length,
      programLimit: ent.limits.programsTracked,
      earningsLocked,
      stats: earningsLocked
        ? { ...stats, totalEarned: null, pending: null } // withhold $ figures
        : stats,
      submissions: rows,
      features: ent.features,
    })
  } catch (error) {
    log.error('failed to load hunt cockpit', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to load hunt data' }, { status: 500 })
  }
}
