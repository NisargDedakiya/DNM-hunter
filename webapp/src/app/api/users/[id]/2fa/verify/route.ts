import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { decryptSecret } from '@/lib/credentialVault'
import { verifyTotpToken } from '@/lib/twoFactor'

interface RouteParams {
  params: Promise<{ id: string }>
}

/** POST /api/users/{id}/2fa/verify — { token } — confirms the pending
 *  secret from .../2fa/setup and flips twoFactorEnabled on. */
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const { token } = await request.json()
    if (!token || typeof token !== 'string') {
      return NextResponse.json({ error: 'token is required' }, { status: 400 })
    }

    const user = await prisma.user.findUnique({ where: { id }, select: { twoFactorSecretEncrypted: true } })
    if (!user?.twoFactorSecretEncrypted) {
      return NextResponse.json({ error: 'No pending 2FA setup — call /2fa/setup first' }, { status: 400 })
    }

    const secret = decryptSecret(user.twoFactorSecretEncrypted)
    const valid = await verifyTotpToken(secret, token)
    if (!valid) {
      return NextResponse.json({ error: 'Invalid code' }, { status: 401 })
    }

    await prisma.user.update({ where: { id }, data: { twoFactorEnabled: true } })
    await prisma.auditLog.create({ data: { userId: id, action: '2fa.enabled', resourceType: 'User', resourceId: id } })

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('2FA verify failed:', error)
    return NextResponse.json({ error: 'Failed to verify 2FA code' }, { status: 500 })
  }
}
