import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { createRequestLogger } from '@/lib/logger'
import { toSarif, toMarkdown, toHtml, type ReportFinding, type ReportMeta } from '@/lib/scan/report'

const CONTENT_TYPE: Record<string, string> = {
  md: 'text/markdown; charset=utf-8',
  html: 'text/html; charset=utf-8',
  sarif: 'application/json; charset=utf-8',
}

// GET /api/scan/shared/[token]/report?format=md|html|sarif — PUBLIC rendered
// report for a shared scan (client delivery). Token is the capability.
export async function GET(request: NextRequest, { params }: { params: Promise<{ token: string }> }) {
  const log = createRequestLogger(request, 'api.scan.shared.report')
  try {
    const { token } = await params
    const format = (new URL(request.url).searchParams.get('format') || 'html').toLowerCase()
    const fmt = format === 'markdown' ? 'md' : format
    if (!(fmt in CONTENT_TYPE)) {
      return NextResponse.json({ error: 'Unsupported format' }, { status: 400 })
    }
    const scan = await prisma.scan.findUnique({ where: { shareToken: token }, include: { findings: true } })
    if (!scan) {
      return NextResponse.json({ error: 'This report link is not valid or was revoked.' }, { status: 404 })
    }
    const meta: ReportMeta = {
      target: scan.target, scanType: scan.scanType, createdAt: scan.createdAt,
      total: scan.total, bySeverity: (scan.bySeverity as Record<string, number>) ?? {}, maxCvss: scan.maxCvss,
    }
    const findings = scan.findings as unknown as ReportFinding[]
    const body = fmt === 'sarif' ? JSON.stringify(toSarif(meta, findings), null, 2)
      : fmt === 'md' ? toMarkdown(meta, findings) : toHtml(meta, findings)
    return new NextResponse(body, {
      status: 200,
      headers: {
        'Content-Type': CONTENT_TYPE[fmt],
        'Content-Disposition': `inline; filename="nisarghunter-report.${fmt}"`,
      },
    })
  } catch (error) {
    log.error('shared report failed', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to render report' }, { status: 500 })
  }
}
