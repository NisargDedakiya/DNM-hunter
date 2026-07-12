import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string }>
}

interface AffectedAsset {
  type?: string
  name?: string
  url?: string
  ip?: string
  port?: number
}

/** GET /api/programs/{id}/memory — return the cached cross-scan memory
 *  record for this program, or null if it has never been computed. */
export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const memory = await prisma.programMemory.findUnique({ where: { programId: id } })
    return NextResponse.json(memory)
  } catch (error) {
    console.error('Fetch program memory failed:', error)
    return NextResponse.json({ error: 'Failed to fetch program memory' }, { status: 500 })
  }
}

/**
 * PATCH /api/programs/{id}/memory — user-authoritative memory edits
 * (master-plan Phase 4). The operator can pin interesting endpoints, edit the
 * freeform note, and record report references. These fields are deliberately
 * NOT touched by the deterministic recompute (POST) below, so a user edit
 * always wins over auto-derived memory. Creates the record if absent.
 */
export async function PATCH(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const program = await prisma.program.findUnique({ where: { id }, select: { id: true } })
    if (!program) return NextResponse.json({ error: 'Program not found' }, { status: 404 })

    const body = await request.json()
    const data: Record<string, unknown> = {}
    if (Array.isArray(body.interestingEndpoints)) data.interestingEndpoints = body.interestingEndpoints
    if (Array.isArray(body.reconSummaries)) data.reconSummaries = body.reconSummaries
    if (Array.isArray(body.reportRefs)) data.reportRefs = body.reportRefs.map(String)
    if (typeof body.userNotes === 'string') data.userNotes = body.userNotes
    if (Object.keys(data).length === 0) {
      return NextResponse.json({ error: 'No editable memory fields provided' }, { status: 400 })
    }

    const memory = await prisma.programMemory.upsert({
      where: { programId: id },
      create: { programId: id, ...data },
      update: data,
    })
    return NextResponse.json(memory)
  } catch (error) {
    console.error('Update program memory failed:', error)
    return NextResponse.json({ error: 'Failed to update program memory' }, { status: 500 })
  }
}

/**
 * POST /api/programs/{id}/memory — deterministically recompute the memory
 * record from this program's full Remediation history (across every
 * Project/scan ever run against it) and upsert.
 *
 * Optional body: { projectId?: string } — the project that triggered the
 * recompute, recorded on lastComputedFromProjectId for traceability.
 *
 * Deliberately Postgres-only (no Neo4j read): Remediation.affectedAssets
 * and validatorStatus already carry everything needed for a useful memory
 * record, and this keeps recompute cheap enough to run after every finding.
 * Richer tech-fingerprint memory sourced from the graph (Wappalyzer-style
 * detections) is a natural follow-up once cross-project graph queries have
 * an established tenant-scoping pattern.
 */
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const program = await prisma.program.findUnique({ where: { id }, select: { id: true } })
    if (!program) {
      return NextResponse.json({ error: 'Program not found' }, { status: 404 })
    }

    let triggeredByProjectId: string | undefined
    try {
      const body = await request.json()
      if (typeof body?.projectId === 'string') triggeredByProjectId = body.projectId
    } catch {
      // no body — fine, recompute doesn't require one
    }

    const remediations = await prisma.remediation.findMany({
      where: { programId: id },
      orderBy: { createdAt: 'desc' },
      select: {
        title: true, category: true, severity: true, validatorStatus: true,
        affectedAssets: true, evidence: true, solution: true, cveIds: true, cweIds: true,
      },
    })

    // ── Known paths: unique affected-asset urls/names across all findings ──
    const pathSet = new Map<string, { path: string; note: string }>()
    for (const r of remediations) {
      const assets = Array.isArray(r.affectedAssets) ? (r.affectedAssets as AffectedAsset[]) : []
      for (const a of assets) {
        const key = a.url || a.name
        if (key && !pathSet.has(key)) {
          pathSet.set(key, { path: key, note: r.title })
        }
      }
    }
    const knownPaths = Array.from(pathSet.values()).slice(0, 100)

    // ── Working payloads: evidence/solution from findings the validator
    // confirmed or marked likely — a future scan shouldn't re-derive these. ──
    const workingPayloads = remediations
      .filter(r => r.validatorStatus === 'confirmed' || r.validatorStatus === 'likely')
      .slice(0, 50)
      .map(r => ({
        category: r.category,
        summary: (r.evidence || r.solution || '').slice(0, 300),
        workedOn: r.title,
      }))
      .filter(p => p.summary.length > 0)

    // ── Tech stack: heuristic — the vulnerability categories a program has
    // repeatedly surfaced are a reasonable proxy for "the kind of stack this
    // is" (e.g. repeated 'sqli' -> SQL backend, repeated 'graphql' -> GraphQL
    // API) until a graph-sourced fingerprint pass replaces this. ──
    const categoryCounts = new Map<string, number>()
    for (const r of remediations) {
      categoryCounts.set(r.category, (categoryCounts.get(r.category) || 0) + 1)
    }
    const techStack = Array.from(categoryCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .map(([category, count]) => ({ name: category, category: 'vuln_surface', confidence: count, source: 'remediation_history' }))

    // ── Prior findings summary: deterministic rollup, this is the block
    // that actually gets injected into the agent's system prompt. ──
    const bySeverity: Record<string, number> = {}
    let confirmedCount = 0
    let needsReviewCount = 0
    for (const r of remediations) {
      bySeverity[r.severity] = (bySeverity[r.severity] || 0) + 1
      if (r.validatorStatus === 'confirmed') confirmedCount++
      if (r.validatorStatus === 'needs_manual_review') needsReviewCount++
    }
    const topCategories = Array.from(categoryCounts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 5)
    const severityLine = Object.entries(bySeverity)
      .sort(([, a], [, b]) => b - a)
      .map(([sev, n]) => `${n} ${sev}`)
      .join(', ')

    const priorFindingsSummary = remediations.length === 0
      ? ''
      : [
          `${remediations.length} prior findings across all scans of this program (${severityLine || 'no severity data'}).`,
          `${confirmedCount} confirmed, ${needsReviewCount} still need manual review.`,
          topCategories.length > 0
            ? `Most common categories: ${topCategories.map(([c, n]) => `${c} (${n})`).join(', ')}.`
            : '',
        ].filter(Boolean).join(' ')

    const memory = await prisma.programMemory.upsert({
      where: { programId: id },
      create: {
        programId: id,
        techStack,
        knownPaths,
        workingPayloads,
        priorFindingsSummary,
        lastComputedFromProjectId: triggeredByProjectId,
      },
      update: {
        techStack,
        knownPaths,
        workingPayloads,
        priorFindingsSummary,
        lastComputedFromProjectId: triggeredByProjectId,
      },
    })

    return NextResponse.json(memory)
  } catch (error) {
    console.error('Recompute program memory failed:', error)
    return NextResponse.json({ error: 'Failed to recompute program memory' }, { status: 500 })
  }
}
