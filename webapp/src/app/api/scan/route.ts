import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireSession } from '@/lib/session'
import { createRequestLogger } from '@/lib/logger'
import { assertFeature, consumeScan } from '@/lib/subscription/entitlements'
import type { Feature } from '@/lib/subscription/plans'
import { runScan, isValidTarget, type ScanType } from '@/lib/scan/runner'

// A scan type maps to the plan feature it requires. 'url' (live HTTP) is on the
// free plan; 'repo' (GitHub clone + full static suite) is a paid capability.
const FEATURE_FOR: Record<ScanType, Feature> = {
  url: 'scan.dast',
  repo: 'scan.github_repo',
}

// GET /api/scan — the signed-in user's scan history (most recent first).
export async function GET(request: NextRequest) {
  const log = createRequestLogger(request, 'api.scan')
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  try {
    const scans = await prisma.scan.findMany({
      where: { userId: session.userId },
      orderBy: { createdAt: 'desc' },
      take: 50,
      select: {
        id: true, target: true, scanType: true, status: true, total: true,
        bySeverity: true, maxCvss: true, createdAt: true,
      },
    })
    return NextResponse.json(scans)
  } catch (error) {
    log.error('failed to list scans', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to list scans' }, { status: 500 })
  }
}

// POST /api/scan  { scanType: 'url'|'repo', target }
// Gates on plan feature (403) and monthly quota (402), runs the scanner,
// persists the scan + findings, and returns them.
export async function POST(request: NextRequest) {
  const log = createRequestLogger(request, 'api.scan')
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  try {
    const body = await request.json().catch(() => ({}))
    const scanType: ScanType = body?.scanType === 'repo' ? 'repo' : 'url'
    const target = String(body?.target ?? '').trim()

    if (!isValidTarget(scanType, target)) {
      return NextResponse.json({ error: 'Invalid or missing target' }, { status: 400 })
    }

    // 1) feature gate
    const denied = await assertFeature(session.userId, FEATURE_FOR[scanType])
    if (denied) {
      return NextResponse.json({ error: denied, code: 'feature_locked' }, { status: 403 })
    }
    // 2) quota gate (atomic consume)
    const quota = await consumeScan(session.userId)
    if (!quota.ok) {
      return NextResponse.json({ error: quota.reason, code: 'quota_exceeded' }, { status: 402 })
    }

    // 3) run
    const result = await runScan(scanType, target)

    // 4) persist (even a failed run is recorded, for the user's history)
    const scan = await prisma.scan.create({
      data: {
        userId: session.userId,
        target,
        scanType,
        status: result.ok ? 'completed' : 'failed',
        total: result.total,
        bySeverity: result.bySeverity,
        maxCvss: result.maxCvss,
        error: result.error ?? null,
        findings: {
          create: result.findings.map((f) => ({
            scanner: f.scanner, ruleId: f.ruleId, title: f.title, severity: f.severity,
            file: f.file, line: f.line, detail: f.detail, vrt: f.vrt, cwe: f.cwe, cvss: f.cvss,
          })),
        },
      },
      include: { findings: true },
    })

    return NextResponse.json(scan, { status: 201 })
  } catch (error) {
    log.error('scan failed', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Scan failed' }, { status: 500 })
  }
}
