import { randomBytes } from 'node:crypto'
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireSession } from '@/lib/session'
import { createRequestLogger } from '@/lib/logger'
import { assertFeature } from '@/lib/subscription/entitlements'

// POST /api/scan/[id]/share — create (or return) a public read-only share link
// for a scan report. Gated on 'report.html' (the client-deliverable is a paid
// feature). Owner only.
export async function POST(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const log = createRequestLogger(request, 'api.scan.share')
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  try {
    const denied = await assertFeature(session.userId, 'report.html')
    if (denied) {
      return NextResponse.json({ error: denied, code: 'feature_locked' }, { status: 403 })
    }
    const { id } = await params
    const scan = await prisma.scan.findUnique({ where: { id }, select: { userId: true, shareToken: true } })
    if (!scan || scan.userId !== session.userId) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 })
    }
    const token = scan.shareToken ?? randomBytes(16).toString('hex')
    if (!scan.shareToken) {
      await prisma.scan.update({ where: { id }, data: { shareToken: token, sharedAt: new Date() } })
    }
    return NextResponse.json({ token, path: `/shared/${token}` })
  } catch (error) {
    log.error('share failed', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to create share link' }, { status: 500 })
  }
}

// DELETE /api/scan/[id]/share — revoke the share link. Owner only.
export async function DELETE(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const log = createRequestLogger(request, 'api.scan.share.revoke')
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  try {
    const { id } = await params
    const scan = await prisma.scan.findUnique({ where: { id }, select: { userId: true } })
    if (!scan || scan.userId !== session.userId) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 })
    }
    await prisma.scan.update({ where: { id }, data: { shareToken: null, sharedAt: null } })
    return NextResponse.json({ ok: true })
  } catch (error) {
    log.error('share revoke failed', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to revoke share link' }, { status: 500 })
  }
}
