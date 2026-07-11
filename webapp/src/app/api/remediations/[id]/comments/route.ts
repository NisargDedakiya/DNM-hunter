import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string }>
}

/** GET /api/remediations/{id}/comments — list comments oldest-first (a
 *  discussion thread reads top-to-bottom). */
export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const comments = await prisma.comment.findMany({
      where: { remediationId: id },
      orderBy: { createdAt: 'asc' },
      include: { user: { select: { id: true, name: true, email: true } } },
    })
    return NextResponse.json(comments)
  } catch (error) {
    console.error('List comments failed:', error)
    return NextResponse.json({ error: 'Failed to list comments' }, { status: 500 })
  }
}

/** POST /api/remediations/{id}/comments — { userId, body } */
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const { userId, body } = await request.json()
    if (!userId || !body || typeof body !== 'string' || !body.trim()) {
      return NextResponse.json({ error: 'userId and a non-empty body are required' }, { status: 400 })
    }

    const remediation = await prisma.remediation.findUnique({ where: { id }, select: { id: true } })
    if (!remediation) {
      return NextResponse.json({ error: 'Remediation not found' }, { status: 404 })
    }

    const comment = await prisma.comment.create({
      data: { remediationId: id, userId, body: body.trim() },
      include: { user: { select: { id: true, name: true, email: true } } },
    })
    return NextResponse.json(comment, { status: 201 })
  } catch (error) {
    console.error('Create comment failed:', error)
    return NextResponse.json({ error: 'Failed to create comment' }, { status: 500 })
  }
}
