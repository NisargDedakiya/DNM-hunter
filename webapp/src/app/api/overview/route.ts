import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireSession } from '@/lib/session'
import { createRequestLogger } from '@/lib/logger'
import { getEntitlements } from '@/lib/subscription/entitlements'
import { computeHunterStats } from '@/lib/hunt/stats'

// GET /api/overview — everything the self-serve home needs in one call:
// the user's plan + quota, their most recent scans, and a bug-hunt pipeline
// summary. Earnings are withheld unless the plan includes 'hunt.earnings'.
export async function GET(request: NextRequest) {
  const log = createRequestLogger(request, 'api.overview')
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  try {
    const ent = await getEntitlements(session.userId)

    const [user, recentScans, scanCount, programs] = await Promise.all([
      prisma.user.findUnique({ where: { id: session.userId }, select: { name: true } }),
      prisma.scan.findMany({
        where: { userId: session.userId },
        orderBy: { createdAt: 'desc' },
        take: 5,
        select: { id: true, target: true, scanType: true, status: true, total: true, maxCvss: true, bySeverity: true, createdAt: true },
      }),
      prisma.scan.count({ where: { userId: session.userId } }),
      prisma.program.findMany({ where: { userId: session.userId }, select: { id: true } }),
    ])

    const submissions = programs.length
      ? await prisma.submission.findMany({
          where: { programId: { in: programs.map((p) => p.id) } },
          select: { status: true, severity: true, bounty: true },
        })
      : []
    const stats = computeHunterStats(submissions)
    const earningsLocked = !ent.features.includes('hunt.earnings')

    return NextResponse.json({
      userName: user?.name ?? '',
      plan: ent.plan,
      planName: ent.planName,
      usage: ent.usage,
      recentScans,
      scanCount,
      programCount: programs.length,
      hunt: {
        earningsLocked,
        totalEarned: earningsLocked ? null : stats.totalEarned,
        openCount: stats.openCount,
        acceptanceRate: stats.acceptanceRate,
        total: stats.total,
      },
      firstRun: scanCount === 0 && submissions.length === 0,
    })
  } catch (error) {
    log.error('failed to load overview', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to load overview' }, { status: 500 })
  }
}
