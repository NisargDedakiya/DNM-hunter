import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string; tokenId: string }>
}

/** DELETE /api/users/{id}/api-tokens/{tokenId} — revoke (soft-delete, keeps
 *  the row for audit purposes; the hash still can't be used to authenticate
 *  once revokedAt is set — checked by the bearer-token auth path). */
export async function DELETE(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id, tokenId } = await params
    const token = await prisma.apiToken.findFirst({ where: { id: tokenId, userId: id } })
    if (!token) {
      return NextResponse.json({ error: 'Token not found' }, { status: 404 })
    }
    await prisma.apiToken.update({ where: { id: tokenId }, data: { revokedAt: new Date() } })
    await prisma.auditLog.create({
      data: { userId: id, action: 'api_token.revoked', resourceType: 'ApiToken', resourceId: tokenId, metadata: { name: token.name } },
    })
    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Revoke API token failed:', error)
    return NextResponse.json({ error: 'Failed to revoke API token' }, { status: 500 })
  }
}
