import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { createRequestLogger } from '@/lib/logger'

interface RouteParams { params: Promise<{ id: string }> }

const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']
const STATUSES = ['draft', 'submitted', 'triaged', 'accepted', 'duplicate', 'rejected', 'paid']
const PLATFORMS = ['hackerone', 'bugcrowd', 'intigriti', 'other']

// GET /api/programs/[id]/submissions — submission history for a program.
export async function GET(request: NextRequest, { params }: RouteParams) {
  const log = createRequestLogger(request, 'api.submissions')
  try {
    const { id: programId } = await params
    const submissions = await prisma.submission.findMany({
      where: { programId },
      orderBy: { createdAt: 'desc' },
    })
    return NextResponse.json(submissions)
  } catch (error) {
    log.error('failed to list submissions', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to list submissions' }, { status: 500 })
  }
}

// POST /api/programs/[id]/submissions — record a new submission.
export async function POST(request: NextRequest, { params }: RouteParams) {
  const log = createRequestLogger(request, 'api.submissions')
  try {
    const { id: programId } = await params
    const body = await request.json()
    if (!body.title || !String(body.title).trim()) {
      return NextResponse.json({ error: 'title is required' }, { status: 400 })
    }
    const severity = SEVERITIES.includes(body.severity) ? body.severity : 'medium'
    const status = STATUSES.includes(body.status) ? body.status : 'draft'
    const platform = PLATFORMS.includes(body.platform) ? body.platform : null

    const program = await prisma.program.findUnique({ where: { id: programId }, select: { id: true } })
    if (!program) return NextResponse.json({ error: 'Program not found' }, { status: 404 })

    const submission = await prisma.submission.create({
      data: {
        programId,
        title: String(body.title).trim(),
        severity,
        status,
        platform,
        bounty: typeof body.bounty === 'number' ? body.bounty : null,
        notes: typeof body.notes === 'string' ? body.notes : '',
        reportId: typeof body.reportId === 'string' ? body.reportId : null,
        submittedAt: status !== 'draft' ? new Date() : null,
      },
    })
    log.info('submission created', { submissionId: submission.id, programId, status })
    return NextResponse.json(submission, { status: 201 })
  } catch (error) {
    log.error('failed to create submission', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to create submission' }, { status: 500 })
  }
}
