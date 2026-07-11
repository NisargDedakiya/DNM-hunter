import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { encryptSecret } from '@/lib/credentialVault'
import { generateTotpSecret, generateQrCodeDataUri, generateBackupCodes } from '@/lib/twoFactor'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * POST /api/users/{id}/2fa/setup — begin enrollment. Generates a secret +
 * backup codes and stores them encrypted, but does NOT enable 2FA yet —
 * that only happens once the user proves they can generate a valid code
 * (POST .../2fa/verify), so a broken authenticator app can't lock anyone
 * out. Calling this again before verifying overwrites the pending secret.
 */
export async function POST(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const user = await prisma.user.findUnique({ where: { id }, select: { email: true } })
    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 })
    }

    const secret = generateTotpSecret()
    const backupCodes = generateBackupCodes()
    const qrCode = await generateQrCodeDataUri(user.email, secret)

    await prisma.user.update({
      where: { id },
      data: {
        twoFactorSecretEncrypted: encryptSecret(secret),
        twoFactorBackupCodesEncrypted: encryptSecret(JSON.stringify(backupCodes)),
        twoFactorEnabled: false,
      },
    })

    return NextResponse.json({ qrCode, secret, backupCodes })
  } catch (error) {
    console.error('2FA setup failed:', error)
    return NextResponse.json({ error: 'Failed to start 2FA setup' }, { status: 500 })
  }
}
