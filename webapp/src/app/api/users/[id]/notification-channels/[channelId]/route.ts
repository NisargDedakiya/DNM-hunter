import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string; channelId: string }>
}

/** PATCH /api/users/{id}/notification-channels/{channelId} — toggle
 *  enabled / update events list (config is set-once via POST, not editable
 *  here — delete and recreate to change the webhook URL). */
export async function PATCH(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, channelId } = await params
    const channel = await prisma.notificationChannel.findFirst({ where: { id: channelId, userId: id } })
    if (!channel) {
      return NextResponse.json({ error: 'Channel not found' }, { status: 404 })
    }
    const body = await request.json()
    const data: { enabled?: boolean; events?: string[] } = {}
    if (typeof body.enabled === 'boolean') data.enabled = body.enabled
    if (Array.isArray(body.events)) data.events = body.events

    const updated = await prisma.notificationChannel.update({
      where: { id: channelId },
      data,
      select: { id: true, name: true, type: true, enabled: true, events: true },
    })
    return NextResponse.json(updated)
  } catch (error) {
    console.error('Update notification channel failed:', error)
    return NextResponse.json({ error: 'Failed to update notification channel' }, { status: 500 })
  }
}

/** DELETE /api/users/{id}/notification-channels/{channelId} */
export async function DELETE(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id, channelId } = await params
    const channel = await prisma.notificationChannel.findFirst({ where: { id: channelId, userId: id } })
    if (!channel) {
      return NextResponse.json({ error: 'Channel not found' }, { status: 404 })
    }
    await prisma.notificationChannel.delete({ where: { id: channelId } })
    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Delete notification channel failed:', error)
    return NextResponse.json({ error: 'Failed to delete notification channel' }, { status: 500 })
  }
}
