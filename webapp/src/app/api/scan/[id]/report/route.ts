import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireSession } from '@/lib/session'
import { createRequestLogger } from '@/lib/logger'
import { assertFeature } from '@/lib/subscription/entitlements'
import type { Feature } from '@/lib/subscription/plans'
import { toSarif, toMarkdown, toHtml, type ReportFinding, type ReportMeta } from '@/lib/scan/report'

// Which plan feature each export format requires. Markdown is available to all;
// HTML (client deliverable) and SARIF (code scanning) are paid.
const FEATURE_FOR_FORMAT: Record<string, Feature | null> = {
  md: null,
  markdown: null,
  html: 'report.html',
  sarif: 'export.sarif',
}

const CONTENT_TYPE: Record<string, string> = {
  md: 'text/markdown; charset=utf-8',
  html: 'text/html; charset=utf-8',
  sarif: 'application/json; charset=utf-8',
}

// GET /api/scan/[id]/report?format=md|html|sarif — the premium deliverable.
export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const log = createRequestLogger(request, 'api.scan.report')
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  try {
    const { id } = await params
    const format = (new URL(request.url).searchParams.get('format') || 'md').toLowerCase()
    const fmt = format === 'markdown' ? 'md' : format
    if (!(fmt in CONTENT_TYPE)) {
      return NextResponse.json({ error: 'Unsupported format' }, { status: 400 })
    }

    const scan = await prisma.scan.findUnique({ where: { id }, include: { findings: true } })
    if (!scan || scan.userId !== session.userId) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 })
    }

    // entitlement gate for paid formats
    const requiredFeature = FEATURE_FOR_FORMAT[fmt]
    if (requiredFeature) {
      const denied = await assertFeature(session.userId, requiredFeature)
      if (denied) {
        return NextResponse.json({ error: denied, code: 'feature_locked' }, { status: 403 })
      }
    }

    const meta: ReportMeta = {
      target: scan.target,
      scanType: scan.scanType,
      createdAt: scan.createdAt,
      total: scan.total,
      bySeverity: (scan.bySeverity as Record<string, number>) ?? {},
      maxCvss: scan.maxCvss,
    }
    const findings = scan.findings as unknown as ReportFinding[]

    let bodyText: string
    if (fmt === 'sarif') bodyText = JSON.stringify(toSarif(meta, findings), null, 2)
    else if (fmt === 'html') bodyText = toHtml(meta, findings)
    else bodyText = toMarkdown(meta, findings)

    const ext = fmt === 'sarif' ? 'sarif' : fmt
    return new NextResponse(bodyText, {
      status: 200,
      headers: {
        'Content-Type': CONTENT_TYPE[fmt],
        'Content-Disposition': `attachment; filename="nisarghunter-report-${id}.${ext}"`,
      },
    })
  } catch (error) {
    log.error('report export failed', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Report export failed' }, { status: 500 })
  }
}
