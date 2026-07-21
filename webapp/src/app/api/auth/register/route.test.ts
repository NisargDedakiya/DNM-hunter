/**
 * Focused tests for POST /api/auth/register (self-serve sign-up).
 *
 * @/lib/prisma and @/lib/auth are mocked so the handler runs without a DB or
 * real crypto. Covers validation, duplicate email, the ALLOW_OPEN_REGISTRATION
 * kill-switch, the forced 'standard' role, and auto sign-in via the auth cookie.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const mockUserCreate = vi.fn()
const mockAuditCreate = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    user: { create: (...a: unknown[]) => mockUserCreate(...a) },
    auditLog: { create: (...a: unknown[]) => mockAuditCreate(...a) },
  },
}))

vi.mock('@/lib/auth', () => ({
  AUTH_COOKIE_NAME: 'nisarghunter-auth',
  hashPassword: vi.fn(async (pw: string) => `hashed:${pw}`),
  createToken: vi.fn(async () => 'signed.jwt.token'),
}))

import { POST } from './route'

function req(body: unknown) {
  return new Request('http://localhost/api/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  }) as never
}

beforeEach(() => {
  mockUserCreate.mockReset()
  mockAuditCreate.mockReset()
  mockAuditCreate.mockResolvedValue({})
  delete process.env.ALLOW_OPEN_REGISTRATION
})

describe('POST /api/auth/register', () => {
  test('creates a standard-role user and signs them in', async () => {
    mockUserCreate.mockResolvedValue({ id: 'u1', name: 'Ada', email: 'ada@example.com', role: 'standard' })

    const res = await POST(req({ name: 'Ada', email: 'Ada@Example.com', password: 'hunter2secret' }))
    expect(res.status).toBe(201)

    const data = await res.json()
    expect(data).toMatchObject({ id: 'u1', email: 'ada@example.com', role: 'standard' })

    // Role is forced to 'standard' and email normalized to lowercase.
    const createArg = mockUserCreate.mock.calls[0][0]
    expect(createArg.data.role).toBe('standard')
    expect(createArg.data.email).toBe('ada@example.com')
    expect(createArg.data.password).toBe('hashed:hunter2secret')

    // Auto sign-in: auth cookie is set.
    expect(res.headers.get('set-cookie')).toContain('nisarghunter-auth=signed.jwt.token')
  })

  test('rejects a short password', async () => {
    const res = await POST(req({ name: 'Ada', email: 'ada@example.com', password: 'short' }))
    expect(res.status).toBe(400)
    expect(mockUserCreate).not.toHaveBeenCalled()
  })

  test('rejects a malformed email', async () => {
    const res = await POST(req({ name: 'Ada', email: 'not-an-email', password: 'longenough1' }))
    expect(res.status).toBe(400)
    expect(mockUserCreate).not.toHaveBeenCalled()
  })

  test('rejects missing fields', async () => {
    const res = await POST(req({ email: 'ada@example.com', password: 'longenough1' }))
    expect(res.status).toBe(400)
  })

  test('maps a duplicate email to 409', async () => {
    mockUserCreate.mockRejectedValue({ code: 'P2002' })
    const res = await POST(req({ name: 'Ada', email: 'ada@example.com', password: 'longenough1' }))
    expect(res.status).toBe(409)
  })

  test('honours the ALLOW_OPEN_REGISTRATION kill-switch', async () => {
    process.env.ALLOW_OPEN_REGISTRATION = 'false'
    const res = await POST(req({ name: 'Ada', email: 'ada@example.com', password: 'longenough1' }))
    expect(res.status).toBe(403)
    expect(mockUserCreate).not.toHaveBeenCalled()
  })
})
