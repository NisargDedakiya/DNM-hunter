import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { decryptSecret } from '@/lib/credentialVault'
import { sendNotification, type NotificationChannelType, type ChannelConfig } from '@/lib/notifications'

interface RouteParams {
  params: Promise<{ id: string; channelId: string }>
}

/** POST /api/users/{id}/notification-channels/{channelId}/test — sends a
 *  real test message through the configured channel so the operator can
 *  confirm the webhook URL/bot token actually works before relying on it. */
export async function POST(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id, channelId } = await params
    const channel = await prisma.notificationChannel.findFirst({ where: { id: channelId, userId: id } })
    if (!channel) {
      return NextResponse.json({ error: 'Channel not found' }, { status: 404 })
    }
    if (!channel.configEncrypted) {
      return NextResponse.json({ error: 'Channel has no configuration' }, { status: 400 })
    }

    const config = JSON.parse(decryptSecret(channel.configEncrypted)) as ChannelConfig
    const result = await sendNotification(channel.type as NotificationChannelType, config, {
      event: 'test',
      title: 'DNM-Hunter — Test Notification',
      message: `This is a test message from the "${channel.name}" notification channel.`,
    })

    if (result.ok) {
      await prisma.notificationChannel.update({ where: { id: channelId }, data: { lastTriggeredAt: new Date() } })
    }

    return NextResponse.json(result, { status: result.ok ? 200 : 502 })
  } catch (error) {
    console.error('Test notification failed:', error)
    return NextResponse.json({ error: 'Failed to send test notification' }, { status: 500 })
  }
}
