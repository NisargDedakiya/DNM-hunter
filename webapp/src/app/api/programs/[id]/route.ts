import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string }>
}

// GET /api/programs/[id] - Program detail with assets and linked projects/findings summary
export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    const program = await prisma.program.findUnique({
      where: { id },
      include: {
        assets: { orderBy: { createdAt: 'desc' } },
        projects: {
          orderBy: { updatedAt: 'desc' },
          select: { id: true, name: true, targetDomain: true, updatedAt: true },
        },
        _count: { select: { remediations: true } },
      },
    })

    if (!program) {
      return NextResponse.json({ error: 'Program not found' }, { status: 404 })
    }

    return NextResponse.json(program)
  } catch (error) {
    console.error('Failed to fetch program:', error)
    return NextResponse.json({ error: 'Failed to fetch program' }, { status: 500 })
  }
}

// PATCH /api/programs/[id] - Update program fields
export async function PATCH(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const body = await request.json()

    const {
      name, platform, platformHandle, platformUrl, status,
      scopeSummary, outOfScope, rateLimits, credentialNotes, notes,
      rewardMin, rewardMax, rewardCurrency, startDate, deadline,
    } = body

    const program = await prisma.program.update({
      where: { id },
      data: {
        ...(name !== undefined && { name }),
        ...(platform !== undefined && { platform }),
        ...(platformHandle !== undefined && { platformHandle }),
        ...(platformUrl !== undefined && { platformUrl }),
        ...(status !== undefined && { status }),
        ...(scopeSummary !== undefined && { scopeSummary }),
        ...(outOfScope !== undefined && { outOfScope }),
        ...(rateLimits !== undefined && { rateLimits }),
        ...(credentialNotes !== undefined && { credentialNotes }),
        ...(notes !== undefined && { notes }),
        ...(rewardMin !== undefined && { rewardMin }),
        ...(rewardMax !== undefined && { rewardMax }),
        ...(rewardCurrency !== undefined && { rewardCurrency }),
        ...(startDate !== undefined && { startDate: startDate ? new Date(startDate) : null }),
        ...(deadline !== undefined && { deadline: deadline ? new Date(deadline) : null }),
      },
    })

    return NextResponse.json(program)
  } catch (error) {
    console.error('Failed to update program:', error)
    return NextResponse.json({ error: 'Failed to update program' }, { status: 500 })
  }
}

// DELETE /api/programs/[id] - Delete a program (assets cascade; projects/remediations unlink)
export async function DELETE(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    await prisma.program.delete({ where: { id } })
    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Failed to delete program:', error)
    return NextResponse.json({ error: 'Failed to delete program' }, { status: 500 })
  }
}
