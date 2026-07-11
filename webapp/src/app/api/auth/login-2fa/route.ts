import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { verifyPassword, createToken, AUTH_COOKIE_NAME } from '@/lib/auth'
import { decryptSecret, encryptSecret } from '@/lib/credentialVault'
import { verifyTotpToken } from '@/lib/twoFactor'

/**
 * POST /api/auth/login-2fa — second step of login when the account has 2FA
 * enabled. Re-verifies email/password (never trust a "step 1 passed" flag
 * from the client) plus a TOTP code OR a one-time backup code, then issues
 * the session cookie exactly like the normal login route.
 */
export async function POST(request: NextRequest) {
  try {
    const { email, password, token, backupCode } = await request.json()

    if (!email || !password || (!token && !backupCode)) {
      return NextResponse.json({ error: 'Email, password, and a code are required' }, { status: 400 })
    }

    const user = await prisma.user.findUnique({
      where: { email },
      select: {
        id: true, name: true, email: true, password: true, role: true,
        twoFactorEnabled: true, twoFactorSecretEncrypted: true, twoFactorBackupCodesEncrypted: true,
      },
    })

    if (!user || !user.password || !(await verifyPassword(password, user.password))) {
      return NextResponse.json({ error: 'Invalid email or password' }, { status: 401 })
    }
    if (!user.twoFactorEnabled) {
      return NextResponse.json({ error: '2FA is not enabled for this account' }, { status: 400 })
    }

    let ok = false
    if (token) {
      const secret = decryptSecret(user.twoFactorSecretEncrypted)
      ok = await verifyTotpToken(secret, token)
    } else if (backupCode) {
      const codes: string[] = user.twoFactorBackupCodesEncrypted
        ? JSON.parse(decryptSecret(user.twoFactorBackupCodesEncrypted))
        : []
      const normalized = backupCode.trim().toUpperCase()
      if (codes.includes(normalized)) {
        ok = true
        // Backup codes are single-use — remove it once consumed.
        const remaining = codes.filter(c => c !== normalized)
        await prisma.user.update({
          where: { id: user.id },
          data: { twoFactorBackupCodesEncrypted: encryptSecret(JSON.stringify(remaining)) },
        })
      }
    }

    if (!ok) {
      await prisma.auditLog.create({ data: { userId: user.id, action: 'login.failed', metadata: { email, reason: '2fa_invalid' } } })
      return NextResponse.json({ error: 'Invalid code' }, { status: 401 })
    }

    const jwt = await createToken(user.id, user.role)
    await prisma.auditLog.create({ data: { userId: user.id, action: 'login.success', metadata: { via: backupCode ? 'backup_code' : 'totp' } } })

    const response = NextResponse.json({ id: user.id, name: user.name, email: user.email, role: user.role })
    response.cookies.set(AUTH_COOKIE_NAME, jwt, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
      path: '/',
      maxAge: 7 * 24 * 60 * 60,
    })
    return response
  } catch (error) {
    console.error('2FA login error:', error)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}
