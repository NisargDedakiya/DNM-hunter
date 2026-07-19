import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { createRequestLogger } from '@/lib/logger'

// GET /api/scan/shared/[token] — PUBLIC read-only view of a shared scan report.
// No auth: the opaque token is the capability. Returns findings but never the
// owner's identity.
export async function GET(request: NextRequest, { params }: { params: Promise<{ token: string }> }) {
  const log = createRequestLogger(request, 'api.scan.shared')
  try {
    const { token } = await params
    if (!token || token.length < 8) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 })
    }
    const scan = await prisma.scan.findUnique({
      where: { shareToken: token },
      include: { findings: true },
    })
    if (!scan) {
      return NextResponse.json({ error: 'This report link is not valid or was revoked.' }, { status: 404 })
    }
    return NextResponse.json({
      target: scan.target,
      scanType: scan.scanType,
      status: scan.status,
      total: scan.total,
      bySeverity: scan.bySeverity,
      maxCvss: scan.maxCvss,
      createdAt: scan.createdAt,
      findings: scan.findings.map((f) => ({
        id: f.id, scanner: f.scanner, ruleId: f.ruleId, title: f.title, severity: f.severity,
        file: f.file, line: f.line, detail: f.detail, vrt: f.vrt, cwe: f.cwe, cvss: f.cvss,
      })),
    }, { headers: { 'Cache-Control': 'private, max-age=60' } })
  } catch (error) {
    log.error('shared view failed', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to load report' }, { status: 500 })
  }
}
