import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { verifyPassword, createToken, AUTH_COOKIE_NAME } from '@/lib/auth'
import { createRequestLogger } from '@/lib/logger'

export async function POST(request: NextRequest) {
  const log = createRequestLogger(request, 'api.auth.login')
  try {
    const { email, password } = await request.json()

    if (!email || !password) {
      return NextResponse.json(
        { error: 'Email and password are required' },
        { status: 400 }
      )
    }

    const user = await prisma.user.findUnique({
      where: { email },
      select: { id: true, name: true, email: true, password: true, role: true, twoFactorEnabled: true },
    })

    if (!user || !user.password) {
      await prisma.auditLog.create({ data: { action: 'login.failed', metadata: { email, reason: 'no_such_user' } } })
      log.warn('login failed: no such user', { email })
      return NextResponse.json(
        { error: 'Invalid email or password' },
        { status: 401 }
      )
    }

    const valid = await verifyPassword(password, user.password)
    if (!valid) {
      await prisma.auditLog.create({ data: { userId: user.id, action: 'login.failed', metadata: { email, reason: 'bad_password' } } })
      log.warn('login failed: bad password', { email, userId: user.id })
      return NextResponse.json(
        { error: 'Invalid email or password' },
        { status: 401 }
      )
    }

    if (user.twoFactorEnabled) {
      // Password is correct but a second factor is required — the client
      // completes login via POST /api/auth/login-2fa with this same email/
      // password plus the TOTP code. No cookie is set yet.
      return NextResponse.json({ requiresTwoFactor: true, email: user.email })
    }

    const token = await createToken(user.id, user.role)
    await prisma.auditLog.create({ data: { userId: user.id, action: 'login.success', metadata: {} } })
    log.info('login succeeded', { userId: user.id, role: user.role })

    const response = NextResponse.json({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    })

    response.cookies.set(AUTH_COOKIE_NAME, token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
      path: '/',
      maxAge: 7 * 24 * 60 * 60, // 7 days
    })

    return response
  } catch (error) {
    log.error('login request failed', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}
