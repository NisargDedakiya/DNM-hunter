import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { decryptSecret } from '@/lib/credentialVault'
import { verifyTotpToken } from '@/lib/twoFactor'

interface RouteParams {
  params: Promise<{ id: string }>
}

/** POST /api/users/{id}/2fa/disable — { token } — requires a currently-
 *  valid code (not just a session) so a stolen session cookie alone can't
 *  turn off the second factor. */
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const { token } = await request.json()
    if (!token || typeof token !== 'string') {
      return NextResponse.json({ error: 'token is required' }, { status: 400 })
    }

    const user = await prisma.user.findUnique({
      where: { id },
      select: { twoFactorSecretEncrypted: true, twoFactorEnabled: true },
    })
    if (!user?.twoFactorEnabled || !user.twoFactorSecretEncrypted) {
      return NextResponse.json({ error: '2FA is not enabled' }, { status: 400 })
    }

    const secret = decryptSecret(user.twoFactorSecretEncrypted)
    const valid = await verifyTotpToken(secret, token)
    if (!valid) {
      return NextResponse.json({ error: 'Invalid code' }, { status: 401 })
    }

    await prisma.user.update({
      where: { id },
      data: { twoFactorEnabled: false, twoFactorSecretEncrypted: '', twoFactorBackupCodesEncrypted: '' },
    })
    await prisma.auditLog.create({ data: { userId: id, action: '2fa.disabled', resourceType: 'User', resourceId: id } })

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('2FA disable failed:', error)
    return NextResponse.json({ error: 'Failed to disable 2FA' }, { status: 500 })
  }
}
