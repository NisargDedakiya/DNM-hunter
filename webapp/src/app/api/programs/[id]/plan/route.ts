import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { buildReconPlan } from '@/lib/reconPlan'
import { createRequestLogger } from '@/lib/logger'

interface RouteParams { params: Promise<{ id: string }> }

// GET /api/programs/[id]/plan — build an approve-before-execute recon plan for a
// program (master-plan Phase 3, Priority 2). Technology signals come from the
// program's remembered tech stack (ProgramMemory, Phase 4); target assets are
// the in-scope assets. Out-of-scope assets are never fed to the plan.
export async function GET(request: NextRequest, { params }: RouteParams) {
  const log = createRequestLogger(request, 'api.plan')
  try {
    const { id } = await params
    const program = await prisma.program.findUnique({
      where: { id },
      include: {
        assets: { where: { inScope: true }, select: { value: true } },
        memory: { select: { techStack: true } },
      },
    })
    if (!program) return NextResponse.json({ error: 'Program not found' }, { status: 404 })

    const assets = program.assets.map(a => a.value)

    // ProgramMemory.techStack is [{ name, ... }] — pull the names when present.
    let detectedTech: string[] = []
    const raw = program.memory?.techStack
    if (Array.isArray(raw)) {
      detectedTech = raw
        .map(t => (t && typeof t === 'object' && 'name' in t ? String((t as { name: unknown }).name) : String(t)))
        .filter(Boolean)
    }

    const plan = buildReconPlan(detectedTech, assets)
    return NextResponse.json({ ...plan, detectedTech, assetCount: assets.length })
  } catch (error) {
    log.error('failed to build recon plan', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to build recon plan' }, { status: 500 })
  }
}
