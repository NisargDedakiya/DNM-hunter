/**
 * Focused tests for /api/users GET + POST RBAC behavior (Phase 16).
 *
 * @/lib/prisma, @/lib/auth, and @/lib/session are mocked so handlers run
 * without a DB or a real auth cookie.
 */

import { describe, test, expect, beforeEach, vi } from 'vitest'

const mockFindMany = vi.fn()
const mockCreate = vi.fn()
const mockGetSession = vi.fn()
const mockIsInternal = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    user: {
      findMany: (...args: unknown[]) => mockFindMany(...args),
      create: (...args: unknown[]) => mockCreate(...args),
    },
  },
}))

vi.mock('@/lib/auth', () => ({
  hashPassword: vi.fn(async (pw: string) => `hashed:${pw}`),
}))

vi.mock('@/lib/session', () => ({
  getSession: (...args: unknown[]) => mockGetSession(...args),
  isInternalRequest: (...args: unknown[]) => mockIsInternal(...args),
}))

import { GET, POST } from './route'

function makeSession(userId = 'user-1', role: 'admin' | 'operator' | 'standard' | 'viewer' = 'standard') {
  return { userId, role }
}

function getReq() {
  return new Request('http://localhost/api/users') as never
}

function postReq(body: unknown) {
  return new Request('http://localhost/api/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }) as never
}

beforeEach(() => {
  mockFindMany.mockReset()
  mockCreate.mockReset()
  mockGetSession.mockReset()
  mockIsInternal.mockReset()
  mockIsInternal.mockReturnValue(false)
  mockFindMany.mockResolvedValue([])
})

describe('GET /api/users - visibility scoping', () => {
  test('a standard user (no users.view_all) is scoped to their own id', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1', 'standard'))
    await GET(getReq())
    expect(mockFindMany.mock.calls[0][0].where).toEqual({ id: 'user-1' })
  })

  test('an operator (no users.view_all) is also scoped to their own id', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1', 'operator'))
    await GET(getReq())
    expect(mockFindMany.mock.calls[0][0].where).toEqual({ id: 'user-1' })
  })

  test('an admin (has users.view_all) sees everyone — no id filter', async () => {
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    await GET(getReq())
    expect(mockFindMany.mock.calls[0][0].where).toEqual({})
  })

  test('internal requests bypass session scoping entirely', async () => {
    mockIsInternal.mockReturnValue(true)
    await GET(getReq())
    expect(mockGetSession).not.toHaveBeenCalled()
    expect(mockFindMany.mock.calls[0][0].where).toEqual({})
  })
})

describe('POST /api/users - creation permission + role whitelist', () => {
  test('403 when the caller lacks users.manage', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1', 'standard'))
    const res = await POST(postReq({ name: 'Eve', email: 'eve@example.com' }))
    expect(res.status).toBe(403)
    expect(mockCreate).not.toHaveBeenCalled()
  })

  test('an operator (no users.manage) also cannot create users', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1', 'operator'))
    const res = await POST(postReq({ name: 'Eve', email: 'eve@example.com' }))
    expect(res.status).toBe(403)
  })

  test('admin can create a user with the new "viewer" role', async () => {
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    mockCreate.mockResolvedValue({ id: 'u-9', name: 'Eve', email: 'eve@example.com', role: 'viewer', createdAt: new Date(), updatedAt: new Date() })
    const res = await POST(postReq({ name: 'Eve', email: 'eve@example.com', role: 'viewer' }))
    expect(res.status).toBe(201)
    expect(mockCreate.mock.calls[0][0].data.role).toBe('viewer')
  })

  test('admin can create a user with the new "operator" role', async () => {
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    mockCreate.mockResolvedValue({ id: 'u-10', name: 'Bob', email: 'bob@example.com', role: 'operator', createdAt: new Date(), updatedAt: new Date() })
    const res = await POST(postReq({ name: 'Bob', email: 'bob@example.com', role: 'operator' }))
    expect(res.status).toBe(201)
    expect(mockCreate.mock.calls[0][0].data.role).toBe('operator')
  })

  test('an unrecognized role string is silently dropped (falls back to schema default)', async () => {
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    mockCreate.mockResolvedValue({ id: 'u-11', name: 'Zed', email: 'zed@example.com', role: 'standard', createdAt: new Date(), updatedAt: new Date() })
    await POST(postReq({ name: 'Zed', email: 'zed@example.com', role: 'superuser' }))
    const data = mockCreate.mock.calls[0][0].data
    expect('role' in data).toBe(false)
  })

  test('internal requests bypass the users.manage check', async () => {
    mockIsInternal.mockReturnValue(true)
    mockCreate.mockResolvedValue({ id: 'u-12', name: 'Svc', email: 'svc@example.com', role: 'standard', createdAt: new Date(), updatedAt: new Date() })
    const res = await POST(postReq({ name: 'Svc', email: 'svc@example.com' }))
    expect(res.status).toBe(201)
    expect(mockGetSession).not.toHaveBeenCalled()
  })
})
