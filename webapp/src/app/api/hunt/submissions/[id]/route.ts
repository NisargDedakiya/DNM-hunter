import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireSession } from '@/lib/session'
import { createRequestLogger } from '@/lib/logger'
import { isSubmissionStatus } from '@/lib/hunt/stats'

// PATCH /api/hunt/submissions/[id]  { status?, bounty? }
// Move a submission through the pipeline and record a bounty. Owner only.
export async function PATCH(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const log = createRequestLogger(request, 'api.hunt.submission.update')
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  try {
    const { id } = await params
    const existing = await prisma.submission.findUnique({
      where: { id },
      include: { program: { select: { userId: true } } },
    })
    if (!existing || existing.program.userId !== session.userId) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 })
    }

    const body = await request.json().catch(() => ({}))
    const data: Record<string, unknown> = {}

    if (body.status !== undefined) {
      if (!isSubmissionStatus(body.status)) {
        return NextResponse.json({ error: 'Invalid status' }, { status: 400 })
      }
      data.status = body.status
      // stamp submittedAt the first time it leaves draft
      if (body.status !== 'draft' && !existing.submittedAt) data.submittedAt = new Date()
    }
    if (body.bounty !== undefined) {
      const b = Number(body.bounty)
      if (Number.isNaN(b) || b < 0) {
        return NextResponse.json({ error: 'Invalid bounty' }, { status: 400 })
      }
      data.bounty = b
    }
    if (Object.keys(data).length === 0) {
      return NextResponse.json({ error: 'Nothing to update' }, { status: 400 })
    }

    const updated = await prisma.submission.update({ where: { id }, data })
    return NextResponse.json(updated)
  } catch (error) {
    log.error('submission update failed', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to update submission' }, { status: 500 })
  }
}
