import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireSession } from '@/lib/session'
import { createRequestLogger } from '@/lib/logger'
import { assertFeature } from '@/lib/subscription/entitlements'
import { remediationFor } from '@/lib/scan/report'

// POST /api/hunt/from-finding  { findingId, programId, platform? }
// Turns a scan finding into a tracked draft submission on one of the hunter's
// programs — the bridge from "scanner found it" to "I'm tracking this bug".
// Gated on the 'hunt.finding_to_submission' feature.
export async function POST(request: NextRequest) {
  const log = createRequestLogger(request, 'api.hunt.from_finding')
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  try {
    const denied = await assertFeature(session.userId, 'hunt.finding_to_submission')
    if (denied) {
      return NextResponse.json({ error: denied, code: 'feature_locked' }, { status: 403 })
    }

    const body = await request.json().catch(() => ({}))
    const findingId = String(body?.findingId ?? '')
    const programId = String(body?.programId ?? '')
    if (!findingId || !programId) {
      return NextResponse.json({ error: 'findingId and programId are required' }, { status: 400 })
    }

    // ownership: the finding's scan and the program must both belong to the user
    const finding = await prisma.scanFinding.findUnique({
      where: { id: findingId },
      include: { scan: { select: { userId: true, target: true } } },
    })
    if (!finding || finding.scan.userId !== session.userId) {
      return NextResponse.json({ error: 'Finding not found' }, { status: 404 })
    }
    const program = await prisma.program.findUnique({ where: { id: programId }, select: { userId: true, platform: true } })
    if (!program || program.userId !== session.userId) {
      return NextResponse.json({ error: 'Program not found' }, { status: 404 })
    }

    const remediation = remediationFor(finding.vrt, finding.severity)
    const notes = [
      `Auto-created from a NisargHunter scan of ${finding.scan.target}.`,
      finding.file ? `Location: ${finding.file}${finding.line ? ':' + finding.line : ''}` : '',
      `Rule: ${finding.ruleId}  ·  VRT: ${finding.vrt || '—'}${finding.cwe ? '  ·  ' + finding.cwe : ''}  ·  CVSS: ${finding.cvss}`,
      '', `Description: ${finding.detail}`, '', `Remediation: ${remediation}`,
    ].filter(Boolean).join('\n')

    const submission = await prisma.submission.create({
      data: {
        programId,
        title: finding.title,
        severity: finding.severity,
        status: 'draft',
        platform: body?.platform ?? program.platform ?? null,
        notes,
      },
    })

    return NextResponse.json(submission, { status: 201 })
  } catch (error) {
    log.error('from-finding failed', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to create submission' }, { status: 500 })
  }
}
