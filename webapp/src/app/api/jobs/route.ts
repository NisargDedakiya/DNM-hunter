import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { createRequestLogger } from '@/lib/logger'

// GET /api/jobs?programId=&status= — the persisted projection of the unified
// scan-lifecycle state machine (master-plan Phase 2, Priority 7). Read-only:
// the orchestrator owns execution; this backs the Phase-5 queue/cockpit UI.
export async function GET(request: NextRequest) {
  const log = createRequestLogger(request, 'api.jobs')
  try {
    const { searchParams } = new URL(request.url)
    const programId = searchParams.get('programId')
    const status = searchParams.get('status')
    const active = searchParams.get('active') // "1" -> only non-terminal jobs

    const where: Record<string, unknown> = {}
    if (programId) where.programId = programId
    if (status) where.status = status
    if (active === '1') where.status = { in: ['queued', 'running', 'paused', 'retrying'] }

    const jobs = await prisma.job.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: 100,
    })
    return NextResponse.json(jobs)
  } catch (error) {
    log.error('failed to list jobs', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to list jobs' }, { status: 500 })
  }
}
