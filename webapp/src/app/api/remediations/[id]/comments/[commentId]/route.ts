import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string; commentId: string }>
}

/** DELETE /api/remediations/{id}/comments/{commentId} */
export async function DELETE(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id, commentId } = await params
    const comment = await prisma.comment.findFirst({ where: { id: commentId, remediationId: id } })
    if (!comment) {
      return NextResponse.json({ error: 'Comment not found' }, { status: 404 })
    }
    await prisma.comment.delete({ where: { id: commentId } })
    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Delete comment failed:', error)
    return NextResponse.json({ error: 'Failed to delete comment' }, { status: 500 })
  }
}
