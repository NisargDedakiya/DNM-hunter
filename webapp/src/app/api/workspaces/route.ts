import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { createRequestLogger } from '@/lib/logger'

// GET /api/workspaces?userId=... — list a user's workspaces with program counts.
// The Workspace is the top-level container of the master-plan Phase 1 spine.
export async function GET(request: NextRequest) {
  const log = createRequestLogger(request, 'api.workspaces')
  try {
    const userId = new URL(request.url).searchParams.get('userId')
    if (!userId) {
      return NextResponse.json({ error: 'userId is required' }, { status: 400 })
    }

    const workspaces = await prisma.workspace.findMany({
      where: { userId },
      orderBy: { createdAt: 'asc' },
      include: { _count: { select: { programs: true } } },
    })

    return NextResponse.json(workspaces)
  } catch (error) {
    log.error('failed to list workspaces', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to list workspaces' }, { status: 500 })
  }
}

// POST /api/workspaces — create a workspace for a user.
export async function POST(request: NextRequest) {
  const log = createRequestLogger(request, 'api.workspaces')
  try {
    const body = await request.json()
    const { userId, name } = body
    if (!userId || !name || !String(name).trim()) {
      return NextResponse.json({ error: 'userId and name are required' }, { status: 400 })
    }

    const workspace = await prisma.workspace.create({
      data: {
        userId,
        name: String(name).trim(),
        description: typeof body.description === 'string' ? body.description : '',
      },
      include: { _count: { select: { programs: true } } },
    })

    log.info('workspace created', { workspaceId: workspace.id, userId })
    return NextResponse.json(workspace, { status: 201 })
  } catch (error) {
    log.error('failed to create workspace', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to create workspace' }, { status: 500 })
  }
}
