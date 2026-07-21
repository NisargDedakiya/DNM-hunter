import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { hashPassword, createToken, AUTH_COOKIE_NAME } from '@/lib/auth'
import { createRequestLogger } from '@/lib/logger'

// Self-serve account registration. New accounts always get the least-privileged
// 'standard' role (never admin) — see lib/rbac.ts. Open sign-up can be turned
// off for a locked-down deployment by setting ALLOW_OPEN_REGISTRATION=false.
const MIN_PASSWORD_LENGTH = 8
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

function registrationEnabled(): boolean {
  return (process.env.ALLOW_OPEN_REGISTRATION ?? 'true').toLowerCase() !== 'false'
}

export async function POST(request: NextRequest) {
  const log = createRequestLogger(request, 'api.auth.register')
  try {
    if (!registrationEnabled()) {
      return NextResponse.json(
        { error: 'Open registration is disabled. Ask an administrator to create your account.' },
        { status: 403 }
      )
    }

    const body = await request.json().catch(() => null)
    if (!body || typeof body !== 'object') {
      return NextResponse.json({ error: 'Invalid request body' }, { status: 400 })
    }

    const name = typeof body.name === 'string' ? body.name.trim() : ''
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : ''
    const password = typeof body.password === 'string' ? body.password : ''

    if (!name || !email || !password) {
      return NextResponse.json(
        { error: 'Name, email and password are required' },
        { status: 400 }
      )
    }
    if (!EMAIL_RE.test(email)) {
      return NextResponse.json({ error: 'Please enter a valid email address' }, { status: 400 })
    }
    if (password.length < MIN_PASSWORD_LENGTH) {
      return NextResponse.json(
        { error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters` },
        { status: 400 }
      )
    }

    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: await hashPassword(password),
        role: 'standard',
      },
      select: { id: true, name: true, email: true, role: true },
    })

    await prisma.auditLog.create({
      data: { userId: user.id, action: 'register.success', metadata: { email } },
    })
    log.info('registration succeeded', { userId: user.id })

    // Sign the new user straight in — same cookie contract as /api/auth/login.
    const token = await createToken(user.id, user.role)
    const response = NextResponse.json(user, { status: 201 })
    response.cookies.set(AUTH_COOKIE_NAME, token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
      path: '/',
      maxAge: 7 * 24 * 60 * 60, // 7 days
    })
    return response
  } catch (error: unknown) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'P2002') {
      // Unique-constraint violation on email — don't reveal more than needed.
      return NextResponse.json(
        { error: 'An account with this email already exists' },
        { status: 409 }
      )
    }
    log.error('registration failed', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}
