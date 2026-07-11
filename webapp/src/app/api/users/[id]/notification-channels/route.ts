import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { encryptSecret } from '@/lib/credentialVault'

interface RouteParams {
  params: Promise<{ id: string }>
}

const VALID_TYPES = ['discord', 'slack', 'telegram', 'webhook']

/** GET /api/users/{id}/notification-channels — list channels. config is
 *  never returned decrypted; only a boolean "configured" flag. */
export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const channels = await prisma.notificationChannel.findMany({
      where: { userId: id },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true, name: true, type: true, enabled: true, events: true,
        lastTriggeredAt: true, createdAt: true, configEncrypted: true,
      },
    })
    return NextResponse.json(channels.map(({ configEncrypted, ...c }) => ({ ...c, configured: !!configEncrypted })))
  } catch (error) {
    console.error('List notification channels failed:', error)
    return NextResponse.json({ error: 'Failed to list notification channels' }, { status: 500 })
  }
}

/** POST /api/users/{id}/notification-channels — { name, type, config, events } */
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const body = await request.json()
    const { name, type, config, events } = body

    if (!name || !VALID_TYPES.includes(type) || !config) {
      return NextResponse.json({ error: `name, type (${VALID_TYPES.join('|')}), and config are required` }, { status: 400 })
    }

    const created = await prisma.notificationChannel.create({
      data: {
        userId: id,
        name,
        type,
        configEncrypted: encryptSecret(JSON.stringify(config)),
        events: Array.isArray(events) ? events : [],
      },
      select: { id: true, name: true, type: true, enabled: true, events: true, createdAt: true },
    })

    return NextResponse.json(created, { status: 201 })
  } catch (error) {
    console.error('Create notification channel failed:', error)
    return NextResponse.json({ error: 'Failed to create notification channel' }, { status: 500 })
  }
}
