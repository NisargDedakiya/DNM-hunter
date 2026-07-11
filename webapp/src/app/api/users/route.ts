import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { hashPassword } from '@/lib/auth'
import { getSession, isInternalRequest } from '@/lib/session'
import { hasPermission, isKnownRole } from '@/lib/rbac'
import { createRequestLogger } from '@/lib/logger'

// GET /api/users - List users (admin: all, standard: self only, internal: all)
export async function GET(request: NextRequest) {
  const log = createRequestLogger(request, 'api.users')
  try {
    let where = {}

    // Internal requests (service-to-service) get all users
    if (!isInternalRequest(request)) {
      const session = await getSession()
      if (!session) {
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
      }
      // Only roles with users.view_all see everyone; others see themselves only
      if (!hasPermission(session.role, 'users.view_all')) {
        where = { id: session.userId }
      }
    }

    const users = await prisma.user.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        password: true,
        createdAt: true,
        updatedAt: true,
        _count: {
          select: { projects: true }
        }
      }
    })

    // Never expose password hash - return hasPassword flag instead
    const safeUsers = users.map(({ password, ...user }) => ({
      ...user,
      hasPassword: password !== '',
    }))

    return NextResponse.json(safeUsers)
  } catch (error) {
    log.error('failed to fetch users', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json(
      { error: 'Failed to fetch users' },
      { status: 500 }
    )
  }
}

// POST /api/users - Create a new user (admin only or internal)
export async function POST(request: NextRequest) {
  const log = createRequestLogger(request, 'api.users')
  try {
    // Allow internal service calls
    if (!isInternalRequest(request)) {
      const session = await getSession()
      if (!session || !hasPermission(session.role, 'users.manage')) {
        return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
      }
    }

    const body = await request.json()
    const { name, email, password, role } = body

    if (!name || !email) {
      return NextResponse.json(
        { error: 'Name and email are required' },
        { status: 400 }
      )
    }

    const user = await prisma.user.create({
      data: {
        name,
        email,
        ...(password ? { password: await hashPassword(password) } : {}),
        ...(role && isKnownRole(role) ? { role } : {}),
      }
    })

    log.info('user created', { userId: user.id, role: user.role })
    return NextResponse.json({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      hasPassword: !!password,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    }, { status: 201 })
  } catch (error: unknown) {
    log.error('failed to create user', { error: error instanceof Error ? error.message : String(error) })

    if (error && typeof error === 'object' && 'code' in error && error.code === 'P2002') {
      return NextResponse.json(
        { error: 'A user with this email already exists' },
        { status: 409 }
      )
    }

    return NextResponse.json(
      { error: 'Failed to create user' },
      { status: 500 }
    )
  }
}
