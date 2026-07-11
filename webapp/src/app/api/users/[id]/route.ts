import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getSession, isInternalRequest } from '@/lib/session'
import { hasPermission, isKnownRole } from '@/lib/rbac'
import { createRequestLogger } from '@/lib/logger'

interface RouteParams {
  params: Promise<{ id: string }>
}

// GET /api/users/[id] - Get user by ID
export async function GET(request: NextRequest, { params }: RouteParams) {
  const log = createRequestLogger(request, 'api.users')
  try {
    const { id } = await params

    // Check permissions: admin or internal can view any user, standard can only view self
    if (!isInternalRequest(request)) {
      const session = await getSession()
      if (!session) {
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
      }
      if (!hasPermission(session.role, 'users.manage') && session.userId !== id) {
        return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
      }
    }

    const user = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        defaultAgentModel: true,
        defaultAiPipelineModel: true,
        twoFactorEnabled: true,
        createdAt: true,
        updatedAt: true,
        projects: {
          orderBy: { createdAt: 'desc' },
          select: {
            id: true,
            name: true,
            targetDomain: true,
            createdAt: true,
            updatedAt: true
          }
        }
      }
    })

    if (!user) {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      )
    }

    return NextResponse.json(user)
  } catch (error) {
    log.error('failed to fetch user', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json(
      { error: 'Failed to fetch user' },
      { status: 500 }
    )
  }
}

// PUT /api/users/[id] - Update user
export async function PUT(request: NextRequest, { params }: RouteParams) {
  const log = createRequestLogger(request, 'api.users')
  try {
    const { id } = await params
    const body = await request.json()
    const { name, email, role, defaultAgentModel, defaultAiPipelineModel } = body

    // Check permissions
    if (!isInternalRequest(request)) {
      const session = await getSession()
      if (!session) {
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
      }

      // Users without users.manage can only update their own name/email
      if (!hasPermission(session.role, 'users.manage') && session.userId !== id) {
        return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
      }

      // Only users.manage can change roles
      if (role && !hasPermission(session.role, 'users.manage')) {
        return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
      }
    }

    const data: Record<string, string> = {}
    if (name) data.name = name
    if (email) data.email = email
    if (role && isKnownRole(role)) data.role = role
    // Remembered model choices, used to pre-fill the next new project.
    if (typeof defaultAgentModel === 'string') data.defaultAgentModel = defaultAgentModel
    if (typeof defaultAiPipelineModel === 'string') data.defaultAiPipelineModel = defaultAiPipelineModel

    const user = await prisma.user.update({
      where: { id },
      data,
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        defaultAgentModel: true,
        defaultAiPipelineModel: true,
        createdAt: true,
        updatedAt: true,
      }
    })

    if (role && isKnownRole(role)) log.info('user role changed', { targetUserId: id, newRole: role })
    return NextResponse.json(user)
  } catch (error: unknown) {
    log.error('failed to update user', { error: error instanceof Error ? error.message : String(error) })

    if (error && typeof error === 'object' && 'code' in error && error.code === 'P2025') {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      )
    }

    return NextResponse.json(
      { error: 'Failed to update user' },
      { status: 500 }
    )
  }
}

// DELETE /api/users/[id] - Delete user (admin only)
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  const log = createRequestLogger(request, 'api.users')
  try {
    const { id } = await params

    if (!isInternalRequest(request)) {
      const session = await getSession()
      if (!session || !hasPermission(session.role, 'users.manage')) {
        return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
      }

      // Prevent self-deletion
      if (session.userId === id) {
        return NextResponse.json(
          { error: 'Cannot delete your own account' },
          { status: 400 }
        )
      }
    }

    await prisma.user.delete({
      where: { id }
    })

    log.info('user deleted', { targetUserId: id })
    return NextResponse.json({ success: true })
  } catch (error: unknown) {
    log.error('failed to delete user', { error: error instanceof Error ? error.message : String(error) })

    if (error && typeof error === 'object' && 'code' in error && error.code === 'P2025') {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      )
    }

    return NextResponse.json(
      { error: 'Failed to delete user' },
      { status: 500 }
    )
  }
}
