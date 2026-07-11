import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { generateApiToken, hashApiToken } from '@/lib/apiTokens'

interface RouteParams {
  params: Promise<{ id: string }>
}

/** GET /api/users/{id}/api-tokens — list tokens (never returns the raw
 *  value or its hash, only display-safe metadata). */
export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const tokens = await prisma.apiToken.findMany({
      where: { userId: id },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true, name: true, tokenPrefix: true,
        lastUsedAt: true, expiresAt: true, revokedAt: true, createdAt: true,
      },
    })
    return NextResponse.json(tokens)
  } catch (error) {
    console.error('List API tokens failed:', error)
    return NextResponse.json({ error: 'Failed to list API tokens' }, { status: 500 })
  }
}

/** POST /api/users/{id}/api-tokens — create a token. The raw value is
 *  returned ONLY in this response; it cannot be retrieved again. */
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const body = await request.json()
    const name = typeof body?.name === 'string' && body.name.trim() ? body.name.trim() : 'Unnamed token'
    const expiresInDays = typeof body?.expiresInDays === 'number' ? body.expiresInDays : null

    const raw = generateApiToken()
    const tokenHash = hashApiToken(raw)
    const tokenPrefix = raw.slice(0, 11)
    const expiresAt = expiresInDays ? new Date(Date.now() + expiresInDays * 86400_000) : null

    const created = await prisma.apiToken.create({
      data: { userId: id, name, tokenHash, tokenPrefix, expiresAt },
      select: { id: true, name: true, tokenPrefix: true, expiresAt: true, createdAt: true },
    })

    await prisma.auditLog.create({
      data: { userId: id, action: 'api_token.created', resourceType: 'ApiToken', resourceId: created.id, metadata: { name } },
    })

    return NextResponse.json({ ...created, token: raw }, { status: 201 })
  } catch (error) {
    console.error('Create API token failed:', error)
    return NextResponse.json({ error: 'Failed to create API token' }, { status: 500 })
  }
}
