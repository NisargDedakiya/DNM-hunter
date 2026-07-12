/**
 * Tests for /api/workspaces (master-plan Phase 1 — Workspace spine).
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const mockFindMany = vi.fn()
const mockCreate = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    workspace: {
      findMany: (...a: unknown[]) => mockFindMany(...a),
      create: (...a: unknown[]) => mockCreate(...a),
    },
  },
}))

const { GET, POST } = await import('./route')

function req(url: string, body?: unknown) {
  return new Request(url, body ? { method: 'POST', body: JSON.stringify(body) } : undefined) as never
}

beforeEach(() => {
  mockFindMany.mockReset()
  mockCreate.mockReset()
})

describe('GET /api/workspaces', () => {
  test('400 without userId', async () => {
    const res = await GET(req('http://localhost/api/workspaces'))
    expect(res.status).toBe(400)
  })

  test('returns a user\'s workspaces scoped by userId', async () => {
    mockFindMany.mockResolvedValue([{ id: 'w1', name: 'Default' }])
    const res = await GET(req('http://localhost/api/workspaces?userId=u1'))
    const body = await res.json()
    expect(res.status).toBe(200)
    expect(body).toHaveLength(1)
    expect(mockFindMany).toHaveBeenCalledWith(expect.objectContaining({ where: { userId: 'u1' } }))
  })
})

describe('POST /api/workspaces', () => {
  test('400 when name is missing', async () => {
    const res = await POST(req('http://localhost/api/workspaces', { userId: 'u1' }))
    expect(res.status).toBe(400)
  })

  test('creates and trims the name', async () => {
    mockCreate.mockResolvedValue({ id: 'w2', name: 'Recon' })
    const res = await POST(req('http://localhost/api/workspaces', { userId: 'u1', name: '  Recon  ' }))
    expect(res.status).toBe(201)
    expect(mockCreate).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ userId: 'u1', name: 'Recon' }),
    }))
  })
})
