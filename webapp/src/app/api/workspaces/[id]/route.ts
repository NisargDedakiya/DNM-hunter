import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { createRequestLogger } from '@/lib/logger'

interface RouteParams { params: Promise<{ id: string }> }

// GET /api/workspaces/[id] — one workspace with its programs (light program shape).
export async function GET(request: NextRequest, { params }: RouteParams) {
  const log = createRequestLogger(request, 'api.workspaces')
  try {
    const { id } = await params
    const workspace = await prisma.workspace.findUnique({
      where: { id },
      include: {
        programs: {
          orderBy: { updatedAt: 'desc' },
          select: { id: true, name: true, platform: true, status: true, updatedAt: true },
        },
      },
    })
    if (!workspace) return NextResponse.json({ error: 'Workspace not found' }, { status: 404 })
    return NextResponse.json(workspace)
  } catch (error) {
    log.error('failed to fetch workspace', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to fetch workspace' }, { status: 500 })
  }
}

// PATCH /api/workspaces/[id] — rename / re-describe.
export async function PATCH(request: NextRequest, { params }: RouteParams) {
  const log = createRequestLogger(request, 'api.workspaces')
  try {
    const { id } = await params
    const body = await request.json()
    const data: { name?: string; description?: string } = {}
    if (typeof body.name === 'string' && body.name.trim()) data.name = body.name.trim()
    if (typeof body.description === 'string') data.description = body.description
    if (Object.keys(data).length === 0) {
      return NextResponse.json({ error: 'Nothing to update' }, { status: 400 })
    }

    const workspace = await prisma.workspace.update({ where: { id }, data })
    log.info('workspace updated', { workspaceId: id })
    return NextResponse.json(workspace)
  } catch (error) {
    log.error('failed to update workspace', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to update workspace' }, { status: 500 })
  }
}

// DELETE /api/workspaces/[id] — remove an empty workspace. Programs are set-null
// on delete by the FK, but we refuse to delete a non-empty workspace so a user
// can't accidentally orphan a stack of programs; they must move/delete programs first.
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  const log = createRequestLogger(request, 'api.workspaces')
  try {
    const { id } = await params
    const count = await prisma.program.count({ where: { workspaceId: id } })
    if (count > 0) {
      return NextResponse.json(
        { error: `Workspace still holds ${count} program(s). Move or delete them first.` },
        { status: 409 },
      )
    }
    await prisma.workspace.delete({ where: { id } })
    log.info('workspace deleted', { workspaceId: id })
    return NextResponse.json({ ok: true })
  } catch (error) {
    log.error('failed to delete workspace', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to delete workspace' }, { status: 500 })
  }
}
