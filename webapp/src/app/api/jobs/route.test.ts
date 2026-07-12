/**
 * Tests for /api/jobs (master-plan Phase 2 — lifecycle projection read API).
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const mockFindMany = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: { job: { findMany: (...a: unknown[]) => mockFindMany(...a) } },
}))

const { GET } = await import('./route')

function req(url: string) {
  return new Request(url) as never
}

beforeEach(() => mockFindMany.mockReset())

describe('GET /api/jobs', () => {
  test('lists all jobs (capped) when no filter given', async () => {
    mockFindMany.mockResolvedValue([{ id: 'j1' }])
    const res = await GET(req('http://localhost/api/jobs'))
    expect(res.status).toBe(200)
    expect(mockFindMany).toHaveBeenCalledWith(expect.objectContaining({ where: {}, take: 100 }))
  })

  test('filters by programId and status', async () => {
    mockFindMany.mockResolvedValue([])
    await GET(req('http://localhost/api/jobs?programId=p1&status=running'))
    expect(mockFindMany).toHaveBeenCalledWith(expect.objectContaining({
      where: { programId: 'p1', status: 'running' },
    }))
  })

  test('active=1 restricts to non-terminal states', async () => {
    mockFindMany.mockResolvedValue([])
    await GET(req('http://localhost/api/jobs?active=1'))
    const call = mockFindMany.mock.calls[0][0]
    expect(call.where.status).toEqual({ in: ['queued', 'running', 'paused', 'retrying'] })
  })
})
