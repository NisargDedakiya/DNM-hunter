/**
 * Tests for /api/workspaces/[id] (master-plan Phase 1).
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const mockFindUnique = vi.fn()
const mockUpdate = vi.fn()
const mockDelete = vi.fn()
const mockProgramCount = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    workspace: {
      findUnique: (...a: unknown[]) => mockFindUnique(...a),
      update: (...a: unknown[]) => mockUpdate(...a),
      delete: (...a: unknown[]) => mockDelete(...a),
    },
    program: { count: (...a: unknown[]) => mockProgramCount(...a) },
  },
}))

const { GET, PATCH, DELETE } = await import('./route')

function req(body?: unknown) {
  return new Request('http://localhost/api/workspaces/w1', body ? { method: 'PATCH', body: JSON.stringify(body) } : undefined) as never
}
const params = { params: Promise.resolve({ id: 'w1' }) }

beforeEach(() => {
  mockFindUnique.mockReset(); mockUpdate.mockReset(); mockDelete.mockReset(); mockProgramCount.mockReset()
})

describe('GET', () => {
  test('404 when missing', async () => {
    mockFindUnique.mockResolvedValue(null)
    const res = await GET(req(), params)
    expect(res.status).toBe(404)
  })
})

describe('PATCH', () => {
  test('400 when nothing to update', async () => {
    const res = await PATCH(req({}), params)
    expect(res.status).toBe(400)
  })
  test('updates the name', async () => {
    mockUpdate.mockResolvedValue({ id: 'w1', name: 'Renamed' })
    const res = await PATCH(req({ name: 'Renamed' }), params)
    expect(res.status).toBe(200)
    expect(mockUpdate).toHaveBeenCalledWith(expect.objectContaining({ data: { name: 'Renamed' } }))
  })
})

describe('DELETE', () => {
  test('409 when the workspace still holds programs', async () => {
    mockProgramCount.mockResolvedValue(3)
    const res = await DELETE(req(), params)
    expect(res.status).toBe(409)
    expect(mockDelete).not.toHaveBeenCalled()
  })
  test('deletes an empty workspace', async () => {
    mockProgramCount.mockResolvedValue(0)
    mockDelete.mockResolvedValue({})
    const res = await DELETE(req(), params)
    expect(res.status).toBe(200)
    expect(mockDelete).toHaveBeenCalled()
  })
})
