import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { createRequestLogger } from '@/lib/logger'

interface RouteParams { params: Promise<{ id: string; submissionId: string }> }

const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']
const STATUSES = ['draft', 'submitted', 'triaged', 'accepted', 'duplicate', 'rejected', 'paid']
const PLATFORMS = ['hackerone', 'bugcrowd', 'intigriti', 'other']

// PATCH /api/programs/[id]/submissions/[submissionId] — update status, bounty, notes, etc.
export async function PATCH(request: NextRequest, { params }: RouteParams) {
  const log = createRequestLogger(request, 'api.submissions')
  try {
    const { id: programId, submissionId } = await params
    const body = await request.json()

    const existing = await prisma.submission.findUnique({ where: { id: submissionId } })
    if (!existing || existing.programId !== programId) {
      return NextResponse.json({ error: 'Submission not found' }, { status: 404 })
    }

    const data: Record<string, unknown> = {}
    if (typeof body.title === 'string' && body.title.trim()) data.title = body.title.trim()
    if (SEVERITIES.includes(body.severity)) data.severity = body.severity
    if (STATUSES.includes(body.status)) {
      data.status = body.status
      // Stamp submittedAt the first time a submission leaves draft.
      if (body.status !== 'draft' && !existing.submittedAt) data.submittedAt = new Date()
    }
    if (body.platform === null || PLATFORMS.includes(body.platform)) data.platform = body.platform
    if (typeof body.bounty === 'number' || body.bounty === null) data.bounty = body.bounty
    if (typeof body.notes === 'string') data.notes = body.notes
    if (typeof body.reportId === 'string' || body.reportId === null) data.reportId = body.reportId

    if (Object.keys(data).length === 0) {
      return NextResponse.json({ error: 'Nothing to update' }, { status: 400 })
    }

    const submission = await prisma.submission.update({ where: { id: submissionId }, data })
    log.info('submission updated', { submissionId, programId })
    return NextResponse.json(submission)
  } catch (error) {
    log.error('failed to update submission', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to update submission' }, { status: 500 })
  }
}

// DELETE /api/programs/[id]/submissions/[submissionId]
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  const log = createRequestLogger(request, 'api.submissions')
  try {
    const { id: programId, submissionId } = await params
    const existing = await prisma.submission.findUnique({ where: { id: submissionId } })
    if (!existing || existing.programId !== programId) {
      return NextResponse.json({ error: 'Submission not found' }, { status: 404 })
    }
    await prisma.submission.delete({ where: { id: submissionId } })
    log.info('submission deleted', { submissionId, programId })
    return NextResponse.json({ ok: true })
  } catch (error) {
    log.error('failed to delete submission', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to delete submission' }, { status: 500 })
  }
}
