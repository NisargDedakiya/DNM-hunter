import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireSession } from '@/lib/session'
import { createRequestLogger } from '@/lib/logger'

// GET /api/scan/[id] — one scan with its findings (owner only).
export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const log = createRequestLogger(request, 'api.scan.detail')
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  try {
    const { id } = await params
    const scan = await prisma.scan.findUnique({
      where: { id },
      include: { findings: true },
    })
    if (!scan || scan.userId !== session.userId) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 })
    }
    return NextResponse.json(scan)
  } catch (error) {
    log.error('failed to load scan', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to load scan' }, { status: 500 })
  }
}

// DELETE /api/scan/[id] — remove a scan (owner only).
export async function DELETE(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const log = createRequestLogger(request, 'api.scan.delete')
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  try {
    const { id } = await params
    const scan = await prisma.scan.findUnique({ where: { id }, select: { userId: true } })
    if (!scan || scan.userId !== session.userId) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 })
    }
    await prisma.scan.delete({ where: { id } })
    return NextResponse.json({ ok: true })
  } catch (error) {
    log.error('failed to delete scan', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to delete scan' }, { status: 500 })
  }
}
